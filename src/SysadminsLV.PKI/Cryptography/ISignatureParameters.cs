#nullable enable
using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents signature algorithm parameters that are encoded in the <strong>parameters</strong> field of
/// signature <see cref="AlgorithmIdentifier"/> (for example, RSASSA-PSS-params or ECDSA-with-Specified).
/// </summary>
public interface ISignatureParameters {
    /// <summary>
    /// Gets the object identifier of the signature algorithm that these parameters belong to.
    /// </summary>
    Oid SignatureAlgorithm { get; }
    /// <summary>
    /// Gets the hash algorithm object identifier.
    /// </summary>
    Oid HashAlgorithm { get; }
    /// <summary>
    /// Encodes signature parameters to ASN.1 DER-encoded byte array.
    /// </summary>
    /// <returns>ASN.1-encoded parameters.</returns>
    Byte[] Encode();
    /// <summary>
    /// Gets the complete signature algorithm identifier that includes encoded parameters.
    /// </summary>
    /// <returns>Signature algorithm identifier.</returns>
    AlgorithmIdentifier ToAlgorithmIdentifier();
}
