#nullable enable
using System;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents RSASSA-PSS signature parameters (RFC 4055, RFC 8017).
/// <code>
/// RSASSA-PSS-params ::= SEQUENCE {
///     hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
///     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
///     saltLength         [2] INTEGER          DEFAULT 20,
///     trailerField       [3] TrailerField     DEFAULT trailerFieldBC
/// }
/// </code>
/// </summary>
/// <remarks>
/// Only MGF1 mask generation function and the default trailer field (<strong>1</strong>) are supported.
/// When encoding, all fields except trailer field are written explicitly.
/// </remarks>
public sealed class RsaPssParameters : ISignatureSchemeParams {
    const Int32 DEFAULT_SALT_LENGTH = 20;

    /// <summary>
    /// Initializes a new instance of the <strong>RsaPssParameters</strong> class from a hash algorithm and a salt length.
    /// MGF1 uses the same hash algorithm as the signature.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm object identifier.</param>
    /// <param name="saltLength">Salt length in bytes.</param>
    /// <exception cref="ArgumentNullException"><strong>hashAlgorithm</strong> parameter is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><strong>saltLength</strong> is negative.</exception>
    internal RsaPssParameters(Oid hashAlgorithm, Int32 saltLength) : this(hashAlgorithm, hashAlgorithm, saltLength) { }
    RsaPssParameters(Oid hashAlgorithm, Oid maskGenHashAlgorithm, Int32 saltLength) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        if (saltLength < 0) {
            throw new ArgumentOutOfRangeException(nameof(saltLength));
        }
        HashAlgorithm = new Oid(hashAlgorithm.Value);
        MaskGenHashAlgorithm = new Oid(maskGenHashAlgorithm.Value);
        SaltLength = saltLength;
    }

    /// <inheritdoc />
    public Oid HashAlgorithm { get; }
    /// <summary>
    /// Gets the hash algorithm used by MGF1 mask generation function.
    /// </summary>
    public Oid MaskGenHashAlgorithm { get; }
    /// <summary>
    /// Gets the salt length in bytes.
    /// </summary>
    public Int32 SaltLength { get; }

    /// <summary>
    /// Creates PSS parameters where the salt length equals the digest length of the specified hash algorithm.
    /// This is the de facto standard value (RFC 8017, TLS 1.3, JWT) and the value used by
    /// <see cref="RSASignaturePadding.Pss"/> in .NET.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm object identifier.</param>
    /// <exception cref="ArgumentNullException"><strong>hashAlgorithm</strong> parameter is null.</exception>
    /// <exception cref="ArgumentException">Hash algorithm is not supported.</exception>
    /// <returns>PSS parameters.</returns>
    internal static RsaPssParameters CreateDefault(Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        return new RsaPssParameters(hashAlgorithm, GetHashLength(hashAlgorithm));
    }
    /// <summary>
    /// Gets the digest length in bytes for a hash algorithm that is supported with PSS.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm object identifier.</param>
    /// <exception cref="ArgumentException">Hash algorithm is not supported.</exception>
    /// <returns>Digest length in bytes.</returns>
    internal static Int32 GetHashLength(Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        return hashAlgorithm.Value switch {
            AlgorithmOid.SHA1   => 20,
            AlgorithmOid.SHA256 => 32,
            AlgorithmOid.SHA384 => 48,
            AlgorithmOid.SHA512 => 64,
            _                   => throw new ArgumentException(
                $"Hash algorithm '{hashAlgorithm.Value}' is not supported with RSASSA-PSS.")
        };
    }
    /// <summary>
    /// Decodes RSASSA-PSS-params structure. Missing fields get their ASN.1 default values.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded RSASSA-PSS-params.</param>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
    /// <exception cref="Asn1InvalidTagException">Data is not a SEQUENCE.</exception>
    /// <exception cref="NotSupportedException">Mask generation function or trailer field is not supported.</exception>
    /// <returns>PSS parameters.</returns>
    internal static RsaPssParameters Decode(Byte[] rawData) {
        if (rawData is null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        var asn = new Asn1Reader(rawData);
        if (asn.Tag != 48) {
            throw new Asn1InvalidTagException(asn.Offset);
        }
        Oid hash = new(AlgorithmOid.SHA1);
        Oid mgfHash = new(AlgorithmOid.SHA1);
        Int32 salt = DEFAULT_SALT_LENGTH;
        if (asn.MoveNext()) {
            do {
                switch (asn.Tag) {
                    case 0xa0:
                        hash = new Oid(new AlgorithmIdentifier(asn.GetPayload()).AlgorithmId.Value);
                        break;
                    case 0xa1:
                        var mgf = new AlgorithmIdentifier(asn.GetPayload());
                        if (mgf.AlgorithmId.Value != AlgorithmOid.Mgf1) {
                            throw new NotSupportedException($"Mask generation function '{mgf.AlgorithmId.Value}' is not supported.");
                        }
                        if (mgf.Parameters is null) {
                            throw new ArgumentException("MGF1 parameters are missing.");
                        }
                        mgfHash = new Oid(new AlgorithmIdentifier(mgf.Parameters).AlgorithmId.Value);
                        break;
                    case 0xa2:
                        salt = (Int32)new Asn1Integer(asn.GetPayload()).Value;
                        break;
                    case 0xa3:
                        if (new Asn1Integer(asn.GetPayload()).Value != 1) {
                            throw new NotSupportedException("Only trailer field value 1 is supported.");
                        }
                        break;
                }
            } while (asn.MoveNextSibling());
        }

        return new RsaPssParameters(hash, mgfHash, salt);
    }

    /// <inheritdoc />
    public Byte[] Encode() {
        // Asn1Builder.Create() wraps the content in an outer SEQUENCE
        return Asn1Builder.Create()
            .AddExplicit(0, x => x.AddSequence(y => y.AddObjectIdentifier(HashAlgorithm)))
            .AddExplicit(1, x => x.AddSequence(y => y
                .AddObjectIdentifier(new Oid(AlgorithmOid.Mgf1))
                .AddSequence(z => z.AddObjectIdentifier(MaskGenHashAlgorithm))))
            .AddExplicit(2, x => x.AddInteger(SaltLength))
            .GetEncoded();
    }
}
