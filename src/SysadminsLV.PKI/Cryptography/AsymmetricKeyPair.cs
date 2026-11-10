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
        Byte[] trimmed = [.. value.SkipWhile(x => x == 0)];

        return trimmed.Length == 0 ? [0] : trimmed;
    }
    /// <summary>
    /// Encodes a raw signature to the format that is stored in the <strong>signatureValue</strong> field of
    /// X.509 certificates, CRLs, CSRs and other signed structures, based on public key algorithm only.
    /// </summary>
    internal static Byte[] EncodeSignature(Oid keyAlgorithm, Byte[] rawSignature) {
        return keyAlgorithm.Value switch {
            AlgorithmOid.ECC or AlgorithmOid.DSA => EncodeRsSignature(rawSignature),
            _ => [.. rawSignature]
        };
    }

    /// <summary>
    /// Creates a signature scheme that is supported by the key pair.
    /// </summary>
    /// <param name="hashAlgorithm">
    /// Optional hash algorithm. Default is <strong>SHA256</strong> (<strong>SHA1</strong> for DSA). Algorithms that don't
    /// use a separate hash ignore this parameter.
    /// </param>
    /// <param name="alternate">
    /// Specifies whether the alternate signature format is used: RSASSA-PSS for RSA keys and ECDSA-with-Specified for
    /// ECDSA keys. The rest is determined by the key algorithm.
    /// </param>
    /// <exception cref="NotSupportedException">
    /// The key pair doesn't have the alternate format, or the hash algorithm is not applicable.
    /// </exception>
    /// <returns>Signature scheme that can be passed to <see cref="SignData(Byte[], SignatureScheme)"/>.</returns>
    public SignatureScheme CreateSignatureScheme(Oid? hashAlgorithm = null, Boolean alternate = false) {
        return CreateSignatureSchemeCore(hashAlgorithm, alternate);
    }
    /// <summary>
    /// Signs the data with the private key by using the default signature scheme of the key pair with the specified hash
    /// algorithm (for example, PKCS#1 v1.5 for RSA).
    /// </summary>
    /// <param name="data">Data to sign.</param>
    /// <param name="hashAlgorithm">Hash algorithm that is used to hash the data.</param>
    /// <exception cref="ArgumentNullException"><strong>data</strong> or <strong>hashAlgorithm</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The key pair contains only public key.</exception>
    /// <exception cref="NotSupportedException">The key doesn't support specified hash algorithm.</exception>
    /// <returns>Raw signature. For ECDSA and DSA it is concatenated <strong>r</strong> and <strong>s</strong> values.</returns>
    public Byte[] SignData(Byte[] data, Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        return SignData(data, CreateSignatureScheme(hashAlgorithm));
    }
    /// <summary>
    /// Signs the data with the private key by using the specified signature scheme.
    /// </summary>
    /// <param name="data">Data to sign.</param>
    /// <param name="scheme">Signature scheme.</param>
    /// <exception cref="ArgumentNullException"><strong>data</strong> or <strong>scheme</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The key pair contains only public key.</exception>
    /// <exception cref="NotSupportedException">The scheme is not applicable to the key or is not implemented by it.</exception>
    /// <returns>Raw signature. For ECDSA and DSA it is concatenated <strong>r</strong> and <strong>s</strong> values.</returns>
    public Byte[] SignData(Byte[] data, SignatureScheme scheme) {
        if (data is null) {
            throw new ArgumentNullException(nameof(data));
        }
        if (scheme is null) {
            throw new ArgumentNullException(nameof(scheme));
        }
        ensureScheme(scheme);
        ensurePrivateKey();

        return SignDataCore(data, scheme);
    }
    /// <summary>
    /// Signs the hash with the private key by using the default signature scheme of the key pair with the specified hash
    /// algorithm.
    /// </summary>
    /// <param name="hash">Hash to sign.</param>
    /// <param name="hashAlgorithm">Hash algorithm that was used to compute the hash.</param>
    /// <exception cref="ArgumentNullException"><strong>hash</strong> or <strong>hashAlgorithm</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The key pair contains only public key.</exception>
    /// <exception cref="NotSupportedException">
    /// The key doesn't support signing pre-computed hash (such as post-quantum algorithms) or specified hash algorithm.
    /// </exception>
    /// <returns>Raw signature.</returns>
    public Byte[] SignHash(Byte[] hash, Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        return SignHash(hash, CreateSignatureScheme(hashAlgorithm));
    }
    /// <summary>
    /// Signs the hash with the private key by using the specified signature scheme.
    /// </summary>
    /// <param name="hash">Hash to sign.</param>
    /// <param name="scheme">Signature scheme. The hash algorithm of the scheme must be the one that was used to compute the hash.</param>
    /// <exception cref="ArgumentNullException"><strong>hash</strong> or <strong>scheme</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The key pair contains only public key.</exception>
    /// <exception cref="NotSupportedException">
    /// The key doesn't support signing pre-computed hash (such as post-quantum algorithms), or the scheme is not applicable
    /// to the key or is not implemented by it.
    /// </exception>
    /// <returns>Raw signature.</returns>
    public Byte[] SignHash(Byte[] hash, SignatureScheme scheme) {
        if (hash is null) {
            throw new ArgumentNullException(nameof(hash));
        }
        if (scheme is null) {
            throw new ArgumentNullException(nameof(scheme));
        }
        ensureScheme(scheme);
        ensurePrivateKey();

        return SignHashCore(hash, scheme);
    }
    /// <summary>
    /// Verifies that the signature matches the data by using the default signature scheme of the key pair with the
    /// specified hash algorithm.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">Raw signature to verify.</param>
    /// <param name="hashAlgorithm">Hash algorithm that is used to hash the data.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>data</strong>, <strong>signature</strong> or <strong>hashAlgorithm</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">The key doesn't support specified hash algorithm.</exception>
    /// <returns><strong>True</strong> if signature is valid, otherwise <strong>False</strong>.</returns>
    public Boolean VerifyData(Byte[] data, Byte[] signature, Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        return VerifyData(data, signature, CreateSignatureScheme(hashAlgorithm));
    }
    /// <summary>
    /// Verifies that the signature matches the data by using the specified signature scheme.
    /// </summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">Raw signature to verify.</param>
    /// <param name="scheme">Signature scheme.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>data</strong>, <strong>signature</strong> or <strong>scheme</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">The scheme is not applicable to the key or is not implemented by it.</exception>
    /// <returns><strong>True</strong> if signature is valid, otherwise <strong>False</strong>.</returns>
    public Boolean VerifyData(Byte[] data, Byte[] signature, SignatureScheme scheme) {
        if (data is null) {
            throw new ArgumentNullException(nameof(data));
        }
        if (signature is null) {
            throw new ArgumentNullException(nameof(signature));
        }
        if (scheme is null) {
            throw new ArgumentNullException(nameof(scheme));
        }
        ensureScheme(scheme);

        return VerifyDataCore(data, signature, scheme);
    }
    /// <summary>
    /// Verifies that the signature matches the hash by using the default signature scheme of the key pair with the
    /// specified hash algorithm.
    /// </summary>
    /// <param name="hash">The hash value of the signed data.</param>
    /// <param name="signature">Raw signature to verify.</param>
    /// <param name="hashAlgorithm">Hash algorithm that was used to compute the hash.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>hash</strong>, <strong>signature</strong> or <strong>hashAlgorithm</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The key doesn't support verifying pre-computed hash (such as post-quantum algorithms) or specified hash algorithm.
    /// </exception>
    /// <returns><strong>True</strong> if signature is valid, otherwise <strong>False</strong>.</returns>
    public Boolean VerifyHash(Byte[] hash, Byte[] signature, Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        return VerifyHash(hash, signature, CreateSignatureScheme(hashAlgorithm));
    }
    /// <summary>
    /// Verifies that the signature matches the hash by using the specified signature scheme.
    /// </summary>
    /// <param name="hash">The hash value of the signed data.</param>
    /// <param name="signature">Raw signature to verify.</param>
    /// <param name="scheme">Signature scheme. The hash algorithm of the scheme must be the one that was used to compute the hash.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>hash</strong>, <strong>signature</strong> or <strong>scheme</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The key doesn't support verifying pre-computed hash (such as post-quantum algorithms), or the scheme is not applicable
    /// to the key or is not implemented by it.
    /// </exception>
    /// <returns><strong>True</strong> if signature is valid, otherwise <strong>False</strong>.</returns>
    public Boolean VerifyHash(Byte[] hash, Byte[] signature, SignatureScheme scheme) {
        if (hash is null) {
            throw new ArgumentNullException(nameof(hash));
        }
        if (signature is null) {
            throw new ArgumentNullException(nameof(signature));
        }
        if (scheme is null) {
            throw new ArgumentNullException(nameof(scheme));
        }
        ensureScheme(scheme);

        return VerifyHashCore(hash, signature, scheme);
    }
    void ensureScheme(SignatureScheme scheme) {
        if (scheme.IsNoSign) {
            throw new NotSupportedException($"The scheme '{scheme.AlgorithmId.Format(true)}' doesn't use a key.");
        }
        if (scheme.KeyAlgorithm?.Value != Oid.Value) {
            throw new NotSupportedException($"The scheme '{scheme.AlgorithmId.Format(true)}' is not applicable to the key algorithm '{Oid.Value}'.");
        }
    }
    void ensurePrivateKey() {
        if (PublicOnly) {
            throw new InvalidOperationException("The key pair doesn't contain a private key.");
        }
    }
    // gets the hash algorithm of hash-based schemes.
    static Oid getHashAlgorithm(SignatureScheme scheme) {
        return scheme.HashAlgorithm ?? throw new NotSupportedException($"The scheme '{scheme.AlgorithmId.Format(true)}' is not based on a separate hash algorithm.");
    }

    /// <summary>
    /// Creates a signature scheme. By default, supports RSA (PKCS#1 v1.5 and PSS), ECDSA (classic and specified) and DSA.
    /// Algorithms that are not based on a separate hash (post-quantum) must override this method.
    /// </summary>
    protected virtual SignatureScheme CreateSignatureSchemeCore(Oid? hashAlgorithm, Boolean alternate) {
        switch (Oid.Value) {
            case AlgorithmOid.RSA:
                Oid rsaHash = hashAlgorithm ?? new Oid(AlgorithmOid.SHA256);
                // alternate format of RSA is RSASSA-PSS
                return alternate
                    ? SignatureScheme.CreatePss(rsaHash)
                    : SignatureScheme.CreateClassic(Oid, rsaHash);
            case AlgorithmOid.ECC:
                Oid ecHash = hashAlgorithm ?? new Oid(AlgorithmOid.SHA256);
                // alternate format of ECDSA is ECDSA-with-Specified
                return alternate
                    ? SignatureScheme.CreateSpecifiedEcdsa(ecHash)
                    : SignatureScheme.CreateClassic(Oid, ecHash);
            case AlgorithmOid.DSA:
                if (alternate) {
                    throw new NotSupportedException("DSA keys don't have alternate signature format.");
                }
                // only SHA1 is supported.
                return SignatureScheme.CreateClassic(Oid, hashAlgorithm ?? new Oid(AlgorithmOid.SHA1));
            default:
                throw new NotSupportedException($"The key algorithm '{Oid.Value}' doesn't support signature schemes.");
        }
    }
    /// <summary>
    /// Signs the data. By default, hashes the data and signs the hash by using <see cref="SignHashCore"/>.
    /// Algorithms that sign the message itself must override this method.
    /// </summary>
    protected virtual Byte[] SignDataCore(Byte[] data, SignatureScheme scheme) {
        Oid hashAlgorithm = getHashAlgorithm(scheme);

        return SignHashCore(HashUtils.ComputeHash(hashAlgorithm, data), scheme);
    }
    /// <summary>
    /// Signs the hash. By default, throws <see cref="NotSupportedException"/>.
    /// </summary>
    protected virtual Byte[] SignHashCore(Byte[] hash, SignatureScheme scheme) {
        throw new NotSupportedException("The algorithm doesn't support signing of pre-computed hash.");
    }
    /// <summary>
    /// Verifies the signature. By default, hashes the data and verifies the hash by using <see cref="VerifyHashCore"/>.
    /// Algorithms that sign the message itself must override this method.
    /// </summary>
    protected virtual Boolean VerifyDataCore(Byte[] data, Byte[] signature, SignatureScheme scheme) {
        Oid hashAlgorithm = getHashAlgorithm(scheme);

        return VerifyHashCore(HashUtils.ComputeHash(hashAlgorithm, data), signature, scheme);
    }
    /// <summary>
    /// Verifies the signature for a hash. By default, throws <see cref="NotSupportedException"/>.
    /// </summary>
    protected virtual Boolean VerifyHashCore(Byte[] hash, Byte[] signature, SignatureScheme scheme) {
        throw new NotSupportedException("The algorithm doesn't support verification of pre-computed hash.");
    }

    /// <summary>
    /// Encodes a raw signature that is returned by <see cref="SignData(Byte[], SignatureScheme)"/> to the format that is stored in the
    /// <strong>signatureValue</strong> field of signed structures (without BIT STRING header and unused-bits byte).
    /// </summary>
    /// <param name="rawSignature">Raw signature.</param>
    /// <returns>Encoded signature.</returns>
    public abstract Byte[] EncodeSignature(Byte[] rawSignature);
    /// <summary>
    /// Decodes a signature that is stored in the <strong>signatureValue</strong> field of signed structures to
    /// a raw signature that is accepted by <see cref="VerifyData(Byte[], Byte[], SignatureScheme)"/>. This is an inverse of <see cref="EncodeSignature(Byte[])"/>.
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
