#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;

namespace SysadminsLV.PKI.Cryptography;
/// <summary>
/// Represents an abstract class for asymmetric key pairs. This class differs from <see cref="AsymmetricAlgorithm"/> by supporting PKCS#1/PKCS#8
/// formats and conversions, and by providing signing and signature verification operations.
/// </summary>
public abstract class AsymmetricKeyPair : IDisposable {
    /// <summary>
    /// Initializes a new instance of <see cref="AsymmetricKeyPair"/> from key algorithm identifier and a boolean value
    /// that indicates whether the key contains only public portion.
    /// </summary>
    /// <param name="keyAlgorithm">Asymmetric algorithm identifier.</param>
    /// <param name="publicOnly"><strong>True</strong> if key is public only, otherwise <strong>False</strong>.</param>
    protected AsymmetricKeyPair(Oid keyAlgorithm, Boolean publicOnly) {
        Oid = keyAlgorithm;
        PublicOnly = publicOnly;
    }

    /// <summary>
    /// Gets the algorithm identifier for the asymmetric algorithm group stored in the current object.
    /// </summary>
    public Oid Oid { get; }
    /// <summary>
    /// Gets the value that indicates whether the current object stores only public part of
    /// key material. If <strong>False</strong>, then object contains both, public and private components.
    /// </summary>
    public Boolean PublicOnly { get; }
    /// <summary>
    /// Gets the key size, in bits.
    /// </summary>
    public abstract Int32 KeySize { get; }

    /// <summary>
    /// Gets a positive integer value without leading zero byte.
    /// </summary>
    /// <param name="rawInteger">Two-complement integer in binary form with optional leading zero.</param>
    /// <returns></returns>
    protected static Byte[] DecodePositiveInteger(Byte[] rawInteger) {
        return rawInteger[0] == 0
            ? [.. rawInteger.Skip(1)]
            : rawInteger;
    }

    /// <summary>
    /// Encodes integer value (in binary form) to a positive ASN.1 Integer. If <strong>rawInteger</strong>
    /// is negative, it is prepended with extra zero to make it positive.
    /// </summary>
    /// <param name="rawInteger">Raw integer to encode.</param>
    /// <returns>ASN.1-encoded integer.</returns>
    protected static Byte[] EncodePositiveInteger(Byte[] rawInteger) {
        var retValue = new List<Byte>(rawInteger.Length + 1);
        if (rawInteger[0] > 127) {
            retValue.Add(0);
        }

        retValue.AddRange(rawInteger);

        return Asn1Utils.Encode(retValue.ToArray(), Asn1Type.INTEGER);
    }
    /// <summary>
    /// Encodes a raw signature that consists of two equally-sized integers, <strong>r</strong> and <strong>s</strong>
    /// (IEEE P1363 format, used by ECDSA and DSA), to <strong>SEQUENCE { INTEGER r, INTEGER s }</strong>.
    /// </summary>
    /// <param name="rawSignature">Concatenated <strong>r</strong> and <strong>s</strong> values.</param>
    /// <exception cref="ArgumentException"><strong>rawSignature</strong> is empty or has odd length.</exception>
    /// <returns>ASN.1-encoded signature.</returns>
    protected static Byte[] EncodeRsSignature(Byte[] rawSignature) {
        if (rawSignature.Length == 0 || rawSignature.Length % 2 != 0) {
            throw new ArgumentException("Signature must consist of two equally-sized integers.", nameof(rawSignature));
        }
        Int32 half = rawSignature.Length / 2;
        return Asn1Builder.Create()
            .AddDerData(EncodePositiveInteger(trimLeadingZeros(rawSignature.Take(half))))
            .AddDerData(EncodePositiveInteger(trimLeadingZeros(rawSignature.Skip(half))))
            .GetEncoded();
    }
    /// <summary>
    /// Decodes <strong>SEQUENCE { INTEGER r, INTEGER s }</strong> to a raw signature (IEEE P1363 format) where both
    /// integers are left-padded to the same size.
    /// </summary>
    /// <param name="encodedSignature">ASN.1-encoded signature.</param>
    /// <param name="elementSize">Size, in bytes, of <strong>r</strong> and <strong>s</strong> values.</param>
    /// <exception cref="CryptographicException">An integer is larger than <strong>elementSize</strong>.</exception>
    /// <returns>Concatenated <strong>r</strong> and <strong>s</strong> values.</returns>
    protected static Byte[] DecodeRsSignature(Byte[] encodedSignature, Int32 elementSize) {
        var asn = new Asn1Reader(encodedSignature);
        if (asn.Tag != 0x30) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        asn.MoveNextAndExpectTags(Asn1Type.INTEGER);
        Byte[] r = DecodePositiveInteger(asn.GetPayload());
        asn.MoveNextSiblingAndExpectTags(Asn1Type.INTEGER);
        Byte[] s = DecodePositiveInteger(asn.GetPayload());
        if (r.Length > elementSize || s.Length > elementSize) {
            throw new CryptographicException("Signature integer is larger than expected.");
        }
        var raw = new Byte[elementSize * 2];
        Buffer.BlockCopy(r, 0, raw, elementSize - r.Length, r.Length);
        Buffer.BlockCopy(s, 0, raw, elementSize * 2 - s.Length, s.Length);

        return raw;
    }
    static Byte[] trimLeadingZeros(IEnumerable<Byte> value) {
        Byte[] trimmed = value.SkipWhile(x => x == 0).ToArray();
        return trimmed.Length == 0 ? [0] : trimmed;
    }
    /// <summary>
    /// Encodes a raw signature to the format that is stored in the <strong>signatureValue</strong> field of
    /// X.509 certificates, CRLs, CSRs and other signed structures, based on public key algorithm only.
    /// </summary>
    internal static Byte[] EncodeSignature(Oid keyAlgorithm, Byte[] rawSignature) {
        switch (keyAlgorithm.Value) {
            case AlgorithmOid.ECC:
            case AlgorithmOid.DSA:
                return EncodeRsSignature(rawSignature);
            default:
                // RSA and post-quantum algorithms store raw signature bytes.
                return rawSignature.ToArray();
        }
    }

    /// <summary>
    /// Signs the data with the private key.
    /// </summary>
    /// <param name="data">Data to sign.</param>
    /// <param name="hashAlgorithm">Hash algorithm that is used to hash the data.</param>
    /// <param name="parameters">
    /// Optional signature parameters. Pass <strong>null</strong> for default signature format of the algorithm.
    /// </param>
    /// <exception cref="ArgumentNullException"><strong>data</strong> or <strong>hashAlgorithm</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The key pair contains only public key.</exception>
    /// <exception cref="NotSupportedException">The key doesn't support specified hash algorithm or parameters.</exception>
    /// <returns>Raw signature. For ECDSA and DSA it is concatenated <strong>r</strong> and <strong>s</strong> values.</returns>
    public Byte[] SignData(Byte[] data, Oid hashAlgorithm, ISignatureParameters? parameters = null) {
        if (data is null) {
            throw new ArgumentNullException(nameof(data));
        }
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        ensurePrivateKey();
        return SignDataCore(data, hashAlgorithm, parameters);
    }
    /// <summary>
    /// Signs the hash with the private key.
    /// </summary>
    /// <param name="hash">Hash to sign.</param>
    /// <param name="hashAlgorithm">Hash algorithm that was used to compute the hash.</param>
    /// <param name="parameters">
    /// Optional signature parameters. Pass <strong>null</strong> for default signature format of the algorithm.
    /// </param>
    /// <exception cref="ArgumentNullException"><strong>hash</strong> or <strong>hashAlgorithm</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The key pair contains only public key.</exception>
    /// <exception cref="NotSupportedException">
    /// The key doesn't support signing pre-computed hash (such as post-quantum algorithms), specified hash algorithm
    /// or parameters.
    /// </exception>
    /// <returns>Raw signature.</returns>
    public Byte[] SignHash(Byte[] hash, Oid hashAlgorithm, ISignatureParameters? parameters = null) {
        if (hash is null) {
            throw new ArgumentNullException(nameof(hash));
        }
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        ensurePrivateKey();
        return SignHashCore(hash, hashAlgorithm, parameters);
    }
    /// <summary>
    /// Verifies that the signature matches the data.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">Raw signature to verify.</param>
    /// <param name="hashAlgorithm">Hash algorithm that is used to hash the data.</param>
    /// <param name="parameters">
    /// Optional signature parameters. Pass <strong>null</strong> for default signature format of the algorithm.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>data</strong>, <strong>signature</strong> or <strong>hashAlgorithm</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">The key doesn't support specified hash algorithm or parameters.</exception>
    /// <returns><strong>True</strong> if signature is valid, otherwise <strong>False</strong>.</returns>
    public Boolean VerifyData(Byte[] data, Byte[] signature, Oid hashAlgorithm, ISignatureParameters? parameters = null) {
        if (data is null) {
            throw new ArgumentNullException(nameof(data));
        }
        if (signature is null) {
            throw new ArgumentNullException(nameof(signature));
        }
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        return VerifyDataCore(data, signature, hashAlgorithm, parameters);
    }
    /// <summary>
    /// Verifies that the signature matches the hash.
    /// </summary>
    /// <param name="hash">The hash value of the signed data.</param>
    /// <param name="signature">Raw signature to verify.</param>
    /// <param name="hashAlgorithm">Hash algorithm that was used to compute the hash.</param>
    /// <param name="parameters">
    /// Optional signature parameters. Pass <strong>null</strong> for default signature format of the algorithm.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <strong>hash</strong>, <strong>signature</strong> or <strong>hashAlgorithm</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The key doesn't support verifying pre-computed hash (such as post-quantum algorithms), specified hash algorithm
    /// or parameters.
    /// </exception>
    /// <returns><strong>True</strong> if signature is valid, otherwise <strong>False</strong>.</returns>
    public Boolean VerifyHash(Byte[] hash, Byte[] signature, Oid hashAlgorithm, ISignatureParameters? parameters = null) {
        if (hash is null) {
            throw new ArgumentNullException(nameof(hash));
        }
        if (signature is null) {
            throw new ArgumentNullException(nameof(signature));
        }
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        return VerifyHashCore(hash, signature, hashAlgorithm, parameters);
    }
    void ensurePrivateKey() {
        if (PublicOnly) {
            throw new InvalidOperationException("The key pair doesn't contain a private key.");
        }
    }

    /// <summary>
    /// Signs the data. By default, hashes the data and signs the hash by using <see cref="SignHashCore"/>.
    /// Algorithms that sign the message itself must override this method.
    /// </summary>
    protected virtual Byte[] SignDataCore(Byte[] data, Oid hashAlgorithm, ISignatureParameters? parameters) {
        return SignHashCore(HashUtils.ComputeHash(hashAlgorithm, data), hashAlgorithm, parameters);
    }
    /// <summary>
    /// Signs the hash. By default, throws <see cref="NotSupportedException"/>.
    /// </summary>
    protected virtual Byte[] SignHashCore(Byte[] hash, Oid hashAlgorithm, ISignatureParameters? parameters) {
        throw new NotSupportedException("The algorithm doesn't support signing of pre-computed hash.");
    }
    /// <summary>
    /// Verifies the signature. By default, hashes the data and verifies the hash by using <see cref="VerifyHashCore"/>.
    /// Algorithms that sign the message itself must override this method.
    /// </summary>
    protected virtual Boolean VerifyDataCore(Byte[] data, Byte[] signature, Oid hashAlgorithm, ISignatureParameters? parameters) {
        return VerifyHashCore(HashUtils.ComputeHash(hashAlgorithm, data), signature, hashAlgorithm, parameters);
    }
    /// <summary>
    /// Verifies the signature for a hash. By default, throws <see cref="NotSupportedException"/>.
    /// </summary>
    protected virtual Boolean VerifyHashCore(Byte[] hash, Byte[] signature, Oid hashAlgorithm, ISignatureParameters? parameters) {
        throw new NotSupportedException("The algorithm doesn't support verification of pre-computed hash.");
    }

    /// <summary>
    /// Encodes a raw signature that is returned by <see cref="SignData"/> to the format that is stored in the
    /// <strong>signatureValue</strong> field of signed structures (without BIT STRING header and unused-bits byte).
    /// </summary>
    /// <param name="rawSignature">Raw signature.</param>
    /// <returns>Encoded signature.</returns>
    public abstract Byte[] EncodeSignature(Byte[] rawSignature);
    /// <summary>
    /// Decodes a signature that is stored in the <strong>signatureValue</strong> field of signed structures to
    /// a raw signature that is accepted by <see cref="VerifyData"/>. This is an inverse of <see cref="EncodeSignature(Byte[])"/>.
    /// </summary>
    /// <param name="encodedSignature">Encoded signature.</param>
    /// <returns>Raw signature.</returns>
    public abstract Byte[] DecodeSignature(Byte[] encodedSignature);

    /// <summary>
    /// Gets the implementation object for the current asymmetric algorithm.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// The algorithm is not implemented by <see cref="AsymmetricAlgorithm"/> (for example, post-quantum algorithms).
    /// </exception>
    /// <exception cref="PlatformNotSupportedException">
    /// Specified asymmetric algorithm is not implemented on a current platform.
    /// </exception>
    /// <returns>
    /// Object that implements particular asymmetric algorithm on a current platform.
    /// </returns>
    [Obsolete("Use SignData/VerifyData/KeySize members of the key pair instead.")]
    public virtual AsymmetricAlgorithm GetAsymmetricKey() {
        throw new NotSupportedException("The algorithm is not implemented by AsymmetricAlgorithm.");
    }
    /// <inheritdoc />
    public abstract void Dispose();
}
