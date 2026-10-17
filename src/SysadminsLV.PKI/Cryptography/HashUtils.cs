#nullable enable
using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Maps hash algorithm object identifiers to platform hash implementations.
/// </summary>
static class HashUtils {
    public static HashAlgorithmName GetName(Oid hashAlgorithm) {
        switch (hashAlgorithm.Value) {
            case AlgorithmOid.MD5:
                return HashAlgorithmName.MD5;
            case AlgorithmOid.SHA1:
                return HashAlgorithmName.SHA1;
            case AlgorithmOid.SHA256:
                return HashAlgorithmName.SHA256;
            case AlgorithmOid.SHA384:
                return HashAlgorithmName.SHA384;
            case AlgorithmOid.SHA512:
                return HashAlgorithmName.SHA512;
            default:
                throw new ArgumentException($"Hash algorithm '{hashAlgorithm.Value}' is not supported.", nameof(hashAlgorithm));
        }
    }
    public static Byte[] ComputeHash(Oid hashAlgorithm, Byte[] data) {
        using var hasher = IncrementalHash.CreateHash(GetName(hashAlgorithm));
        hasher.AppendData(data);
        return hasher.GetHashAndReset();
    }
}
