#nullable enable
using System;
using System.Security.Cryptography;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a scheme information of classic composite signature algorithms, such as <strong>sha256RSA</strong>,
/// <strong>sha384ECDSA</strong> or <strong>sha1DSA</strong> (and NoSign identifiers, such as <strong>sha1NoSign</strong>).
/// The hash algorithm is implied by the algorithm identifier and is not stored in the parameters field.
/// </summary>
public sealed class ClassicSignatureSchemeParams : ISignatureSchemeParams {
    internal ClassicSignatureSchemeParams(Oid hashAlgorithm, Boolean encodeNull) {
        HashAlgorithm = new Oid(hashAlgorithm.Value);
        EncodeNull = encodeNull;
    }

    /// <inheritdoc />
    public Oid HashAlgorithm { get; }
    /// <summary>
    /// Gets the value that indicates whether the <strong>parameters</strong> field of algorithm identifier contains
    /// ASN.1 NULL (RSA and NoSign identifiers) or is absent (ECDSA and DSA).
    /// </summary>
    public Boolean EncodeNull { get; }

    /// <inheritdoc />
    public Byte[]? Encode() {
        return EncodeNull
            ? new Asn1Null().GetRawDataAsMemory().ToArray()
            : null;
    }
}
