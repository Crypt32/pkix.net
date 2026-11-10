#nullable enable
using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// RSA signing and verification shared by RSA key pair implementations.
/// </summary>
static class RsaSignatureHelper {
    public static Byte[] SignHash(RSA key, Byte[] hash, SignatureScheme scheme) {
        Oid hashAlgorithm = getHashAlgorithm(scheme);
        return key.SignHash(hash, HashUtils.GetName(hashAlgorithm), getPadding(hashAlgorithm, scheme));
    }
    public static Boolean VerifyHash(RSA key, Byte[] hash, Byte[] signature, SignatureScheme scheme) {
        Oid hashAlgorithm = getHashAlgorithm(scheme);
        return key.VerifyHash(hash, signature, HashUtils.GetName(hashAlgorithm), getPadding(hashAlgorithm, scheme));
    }

    static Oid getHashAlgorithm(SignatureScheme scheme) {
        return scheme.HashAlgorithm ?? throw new NotSupportedException($"The scheme '{scheme.AlgorithmId.Format(true)}' is not based on a separate hash algorithm.");
    }
    static RSASignaturePadding getPadding(Oid hashAlgorithm, SignatureScheme scheme) {
        switch (scheme.Parameters) {
            case ClassicSignatureSchemeParams:
                return RSASignaturePadding.Pkcs1;
            case RsaPssParameters pss:
                if (pss.HashAlgorithm.Value != hashAlgorithm.Value || pss.MaskGenHashAlgorithm.Value != hashAlgorithm.Value) {
                    throw new NotSupportedException("RSASSA-PSS parameters must use the same hash algorithm for the signature and MGF1.");
                }
                // cross-platform PSS uses salt length that is equal to hash length.
                if (pss.SaltLength != RsaPssParameters.GetHashLength(hashAlgorithm)) {
                    throw new NotSupportedException("RSASSA-PSS salt length other than the hash length is not supported.");
                }
                return RSASignaturePadding.Pss;
            default:
                throw new NotSupportedException($"The scheme '{scheme.AlgorithmId.Format(true)}' is not supported by RSA keys.");
        }
    }
}
/// <summary>
/// ECDSA signing and verification shared by ECDSA key pair implementations.
/// </summary>
static class EcdsaSignatureHelper {
    public static Byte[] SignHash(ECDsa key, Byte[] hash, SignatureScheme scheme) {
        validate(scheme);
        return key.SignHash(hash);
    }
    public static Boolean VerifyHash(ECDsa key, Byte[] hash, Byte[] signature, SignatureScheme scheme) {
        validate(scheme);
        return key.VerifyHash(hash, signature);
    }

    static void validate(SignatureScheme scheme) {
        // classic and specified ECDSA differ only in the identifier, the signature is the same.
        if (scheme.Parameters is not (ClassicSignatureSchemeParams or SpecifiedEcdsaParameters)) {
            throw new NotSupportedException($"The scheme '{scheme.AlgorithmId.Format(true)}' is not supported by ECDSA keys.");
        }
    }
}
/// <summary>
/// DSA signing and verification shared by DSA key pair implementations.
/// </summary>
static class DsaSignatureHelper {
    public static Byte[] SignHash(DSA key, Byte[] hash, SignatureScheme scheme) {
        validate(scheme);
        return key.CreateSignature(hash);
    }
    public static Boolean VerifyHash(DSA key, Byte[] hash, Byte[] signature, SignatureScheme scheme) {
        validate(scheme);
        return key.VerifySignature(hash, signature);
    }

    static void validate(SignatureScheme scheme) {
        if (scheme.Parameters is not ClassicSignatureSchemeParams) {
            throw new NotSupportedException($"The scheme '{scheme.AlgorithmId.Format(true)}' is not supported by DSA keys.");
        }
    }
}
