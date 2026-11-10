#nullable enable
using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents additional information about a <see cref="SignatureScheme"/>. This is a broader term than ASN.1
/// parameters of <see cref="AlgorithmIdentifier"/>: it describes the hash algorithm, padding/format details, nested
/// schemes of composite algorithms and so on, even when that information is not stored in the identifier itself.
/// The only requirement is that the scheme can be read from and written to the correct binary representation.
/// </summary>
/// <remarks>
/// Scheme parameters cannot live on their own: they get the meaning from the <see cref="SignatureScheme.AlgorithmId"/>
/// of the scheme they are attached to. Signature schemes without any additional information (pure ML-DSA and
/// SLH-DSA) have no parameters at all.
/// </remarks>
public interface ISignatureSchemeParams {
    /// <summary>
    /// Gets the hash algorithm that is used by the scheme to hash the message. For composite schemes this is
    /// the pre-hash algorithm of the composite signature.
    /// </summary>
    Oid HashAlgorithm { get; }
    /// <summary>
    /// Encodes the information that is stored in the <strong>parameters</strong> field of
    /// <see cref="AlgorithmIdentifier"/>.
    /// </summary>
    /// <returns>
    /// ASN.1-encoded parameters, or <strong>null</strong> if the <strong>parameters</strong> field must be absent.
    /// </returns>
    Byte[]? Encode();
}
