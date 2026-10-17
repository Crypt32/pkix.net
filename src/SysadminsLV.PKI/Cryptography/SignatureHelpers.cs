#nullable enable
using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// RSA signing and verification shared by RSA key pair implementations.
/// </summary>
static class RsaSignatureHelper {
    public static Byte[] SignHash(RSA key, Byte[] hash, Oid hashAlgorithm, ISignatureParameters? parameters) {
        return key.SignHash(hash, HashUtils.GetName(hashAlgorithm), getPadding(hashAlgorithm, parameters));
    }
    public static Boolean VerifyHash(RSA key, Byte[] hash, Byte[] signature, Oid hashAlgorithm, ISignatureParameters? parameters) {
        return key.VerifyHash(hash, signature, HashUtils.GetName(hashAlgorithm), getPadding(hashAlgorithm, parameters));
    }

    static RSASignaturePadding getPadding(Oid hashAlgorithm, ISignatureParameters? parameters) {
        switch (parameters) {
            case null:
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
                throw new NotSupportedException($"Signature parameters '{parameters.GetType().Name}' are not supported by RSA keys.");
        }
    }
}
/// <summary>
/// ECDSA signing and verification shared by ECDSA key pair implementations.
/// </summary>
static class EcdsaSignatureHelper {
    public static Byte[] SignHash(ECDsa key, Byte[] hash, Oid hashAlgorithm, ISignatureParameters? parameters) {
        validate(hashAlgorithm, parameters);
        return key.SignHash(hash);
    }
    public static Boolean VerifyHash(ECDsa key, Byte[] hash, Byte[] signature, Oid hashAlgorithm, ISignatureParameters? parameters) {
        validate(hashAlgorithm, parameters);
        return key.VerifyHash(hash, signature);
    }

    static void validate(Oid hashAlgorithm, ISignatureParameters? parameters) {
        switch (parameters) {
            case null:
                return;
            case SpecifiedEcdsaParameters specified:
                if (specified.HashAlgorithm.Value != hashAlgorithm.Value) {
                    throw new NotSupportedException("ECDSA-with-Specified parameters must use the same hash algorithm as the signature.");
                }
                return;
            default:
                throw new NotSupportedException($"Signature parameters '{parameters.GetType().Name}' are not supported by ECDSA keys.");
        }
    }
}
/// <summary>
/// DSA signing and verification shared by DSA key pair implementations.
/// </summary>
static class DsaSignatureHelper {
    public static Byte[] SignHash(DSA key, Byte[] hash, ISignatureParameters? parameters) {
        validate(parameters);
        return key.CreateSignature(hash);
    }
    public static Boolean VerifyHash(DSA key, Byte[] hash, Byte[] signature, ISignatureParameters? parameters) {
        validate(parameters);
        return key.VerifySignature(hash, signature);
    }

    static void validate(ISignatureParameters? parameters) {
        if (parameters is not null) {
            throw new NotSupportedException("DSA signature doesn't support additional parameters.");
        }
    }
}
