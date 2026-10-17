#nullable enable
using System;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents ECDSA-with-Specified signature parameters (RFC 5758). The parameters are a hash algorithm
/// identifier.
/// </summary>
public sealed class SpecifiedEcdsaParameters : ISignatureParameters {
    /// <summary>
    /// Initializes a new instance of the <strong>SpecifiedEcdsaParameters</strong> class from a hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm object identifier.</param>
    /// <exception cref="ArgumentNullException"><strong>hashAlgorithm</strong> parameter is null.</exception>
    public SpecifiedEcdsaParameters(Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }
        HashAlgorithm = new Oid(hashAlgorithm.Value);
    }

    /// <inheritdoc />
    public Oid SignatureAlgorithm => new(AlgorithmOid.ECDSA_SPECIFIED);
    /// <inheritdoc />
    public Oid HashAlgorithm { get; }

    /// <summary>
    /// Decodes ECDSA-with-Specified parameters (a hash <see cref="AlgorithmIdentifier"/>).
    /// </summary>
    /// <param name="rawData">ASN.1-encoded hash algorithm identifier.</param>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null.</exception>
    /// <exception cref="Asn1InvalidTagException">Data is not a SEQUENCE.</exception>
    /// <returns>ECDSA-with-Specified parameters.</returns>
    public static SpecifiedEcdsaParameters Decode(Byte[] rawData) {
        if (rawData is null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        return new SpecifiedEcdsaParameters(new AlgorithmIdentifier(rawData).AlgorithmId);
    }

    /// <inheritdoc />
    public Byte[] Encode() {
        return new AlgorithmIdentifier(HashAlgorithm, new Asn1Null().GetRawDataAsMemory().ToArray()).RawData;
    }
    /// <inheritdoc />
    public AlgorithmIdentifier ToAlgorithmIdentifier() {
        return new AlgorithmIdentifier(SignatureAlgorithm, Encode());
    }
}
