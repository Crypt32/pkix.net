#nullable enable
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a cross-platform digital signature generator and validator.
/// </summary>
public class CryptSigner : ICryptSigner, IDisposable {
    const String DEFAULT_HASH_ALG = AlgorithmOid.SHA256;

    readonly Boolean ownsKeyPairs;
    Boolean nullSigned;
    AsymmetricKeyPair? pubKeyPair, privKeyPair;
    Oid hashAlgorithm;
    Oid? sigAlgorithm;
    ISignatureParameters? sigParams;
    RSASignaturePadding paddingScheme = RSASignaturePadding.Pkcs1;
    Int32 pssSaltByteCount;
    KeyType keyType;

    /// <summary>
    /// Initializes a new instance of <strong>CryptSigner</strong> from an asymmetric key pair and optional
    /// hashing algorithm.
    /// </summary>
    /// <param name="keyPair">An asymmetric key instance.</param>
    /// <param name="hashingAlgorithm">Optional hashing algorithm. Default is <strong>SHA256</strong>.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>keyPair</strong> parameter is null.
    /// </exception>
    /// <remarks>The signer doesn't take ownership of <strong>keyPair</strong>. The caller is responsible for disposing it.</remarks>
    public CryptSigner(AsymmetricKeyPair keyPair, Oid? hashingAlgorithm = null) : this(keyPair, hashingAlgorithm, false) { }
    CryptSigner(AsymmetricKeyPair keyPair, Oid? hashingAlgorithm, Boolean ownsKeys) {
        if (keyPair is null) {
            throw new ArgumentNullException(nameof(keyPair));
        }

        ownsKeyPairs = ownsKeys;
        PublicKeyAlgorithm = setKeyPair(keyPair);
        hashAlgorithm = getHashAlgorithm(hashingAlgorithm ?? new Oid(DEFAULT_HASH_ALG));
    }

    /// <summary>
    /// Initializes a new instance of the <strong>CryptSigner</strong> class from signer certificate and
    /// client-provided hash algorithm.
    /// </summary>
    /// <param name="certificate">Signer certificate with associated private key.</param>
    /// <param name="hashingAlgorithm">
    /// Hash algorithm that is used to calculate the hash during signing or signature verification
    /// processes.
    /// </param>
    /// <exception cref="ArgumentException">
    ///     <strong>hashAlgorithm</strong> parameter contains invalid hash algorithm identifier.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <strong>signer</strong> and/or <strong>hashAlgorithm</strong> parameter is null.
    /// </exception>
    /// <remarks>
    /// Currently, the following hash algorithms are supported:
    /// <list type="bullet">
    ///     <item>MD5</item>
    ///     <item>SHA1</item>
    ///     <item>SHA256</item>
    ///     <item>SHA384</item>
    ///     <item>SHA512</item>
    /// </list>
    /// Hash algorithm is ignored for DSA keys and is automatically set to 'SHA1'.
    /// </remarks>
    public CryptSigner(X509Certificate2 certificate, Oid? hashingAlgorithm) {
        SignerCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        ownsKeyPairs = true;
        PublicKeyAlgorithm = setKeyPair(certificate.PublicKey.GetAsymmetricKeyPair());
        hashAlgorithm = getHashAlgorithm(hashingAlgorithm ?? new Oid(DEFAULT_HASH_ALG));
    }

    /// <summary>
    /// Gets the certificate associated with the current instance of <strong>MessageSigner</strong>.
    /// </summary>
    public X509Certificate2? SignerCertificate { get; private set; }
    /// <summary>
    /// Gets public key algorithm.
    /// </summary>
    public Oid PublicKeyAlgorithm { get; }
    /// <summary>
    /// Gets or sets the hashing algorithm that is used to calculate the hash during signing or signature verification
    /// processes.
    /// </summary>
    public Oid HashingAlgorithm {
        get => new(hashAlgorithm);
        set {
            Oid newHash = getHashAlgorithm(value);
            if (sigParams is not null && newHash.Value != sigParams.HashAlgorithm.Value) {
                throw new InvalidOperationException("Hash algorithm is defined by SignatureParameters. Assign new parameters instead.");
            }
            hashAlgorithm = newHash;
        }
    }
    /// <summary>
    /// Gets resulting signature algorithm identifier.
    /// </summary>
    public Oid SignatureAlgorithm => new(sigAlgorithm!);
    /// <summary>
    /// Gets or sets signature padding scheme for RSA signature creation and validation.
    /// Default is <strong>PKCS1</strong>.
    /// </summary>
    [Obsolete("Use SignatureParameters property with RsaPssParameters instead.")]
    public RSASignaturePadding PaddingScheme {
        get => paddingScheme;
        set => paddingScheme = value ?? throw new ArgumentNullException(nameof(value));
    }
    /// <summary>
    /// Gets or sets the size, in bytes, of the random salt to use for the PSS padding.
    /// Default value matches the hash output length: 16 bytes for MD5, 20 bytes for SHA1, 32 bytes for
    /// SHA256, 48 bytes for SHA384 and 64 bytes for SHA512 hashing algorithm.
    /// </summary>
    /// <remarks>
    /// The cross-platform implementation supports only the salt length that is equal to the hash length. Any other
    /// value causes <see cref="NotSupportedException"/> during signing and signature verification.
    /// </remarks>
    [Obsolete("Use SignatureParameters property with RsaPssParameters instead.")]
    public Int32 PssSaltByteCount {
        get => pssSaltByteCount;
        set => pssSaltByteCount = value;
    }
    /// <summary>
    /// Gets or sets signature parameters: RSASSA-PSS parameters for RSA keys or specified ECDSA parameters for
    /// ECDSA keys. When set, parameters define the hash algorithm of the signer. <strong>Null</strong> resets the signer
    /// to the default signature format: PKCS#1 v1.5 for RSA, plain ECDSA, DSA.
    /// </summary>
    /// <exception cref="NotSupportedException">The parameters are not applicable to the signer's key algorithm.</exception>
    /// <exception cref="InvalidOperationException">
    /// Parameters are set and the hash algorithm of the signer is changed to a different value.
    /// </exception>
    public ISignatureParameters? SignatureParameters {
        get => getSignatureParameters();
        set {
            if (value is null) {
                sigParams = null;
                paddingScheme = RSASignaturePadding.Pkcs1;
            } else {
                validateParameters(value);
                sigParams = value;
                hashAlgorithm = new Oid(value.HashAlgorithm);
            }
            sigAlgorithm = null;
        }
    }

    // returns public key algorithm
    Oid setKeyPair(AsymmetricKeyPair keyPair) {
        switch (keyPair.Oid.Value) {
            case AlgorithmOid.ECC:
                keyType = KeyType.EcDsa;
                break;
            case AlgorithmOid.RSA:
                keyType = KeyType.Rsa;
                break;
            case AlgorithmOid.DSA:
                keyType = KeyType.Dsa;
                break;
            default:
                throw new NotSupportedException("Public key algorithm is not supported.");
        }
        // private key pair is capable of signature verification too.
        pubKeyPair = keyPair;
        if (!keyPair.PublicOnly) {
            privKeyPair = keyPair;
        }

        return keyPair.Oid;
    }
    Oid getHashAlgorithm(Oid hashAlg) {
        Oid oid;
        try {
            oid = Oid.FromOidValue(hashAlg.Value, OidGroup.HashAlgorithm);
        } catch {
            oid = mapSignatureAlgorithmToHashAlgorithm(hashAlg.Value!, null);
        }

        switch (keyType) {
            case KeyType.Rsa:
                switch (oid.Value) {
                    case AlgorithmOid.MD5: // md5
                        pssSaltByteCount = 16;
                        break;
                    case AlgorithmOid.SHA1: // sha1
                        pssSaltByteCount = 20;
                        break;
                    case AlgorithmOid.SHA256: // sha256
                        pssSaltByteCount = 32;
                        break;
                    case AlgorithmOid.SHA384: // sha384
                        pssSaltByteCount = 48;
                        break;
                    case AlgorithmOid.SHA512: // sha512
                        pssSaltByteCount = 64;
                        break;
                }
                break;
            case KeyType.Dsa:
                // force SHA1 for DSA keys
                oid = new Oid(AlgorithmOid.SHA1);
                break;
        }

        return oid;
    }
    Oid mapSignatureAlgorithmToHashAlgorithm(String signatureOid, Asn1Reader? asn) {
        switch (signatureOid) {
            // md5
            case AlgorithmOid.MD5:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.MD5_RSA:
                return new Oid(AlgorithmOid.MD5);
            // sha1
            case AlgorithmOid.SHA1:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.SHA1_ECDSA:
            case AlgorithmOid.SHA1_RSA:
            case AlgorithmOid.SHA1_DSA:
                return new Oid(AlgorithmOid.SHA1);
            // sha256
            case AlgorithmOid.SHA256:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.SHA256_ECDSA:
            case AlgorithmOid.SHA256_RSA:
                return new Oid(AlgorithmOid.SHA256);
            // sha384
            case AlgorithmOid.SHA384:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.SHA384_ECDSA:
            case AlgorithmOid.SHA384_RSA:
                return new Oid(AlgorithmOid.SHA384);
            // sha512
            case AlgorithmOid.SHA512:
                nullSigned = true;
                return new Oid(signatureOid);
            case AlgorithmOid.SHA512_ECDSA:
            case AlgorithmOid.SHA512_RSA:
                return new Oid(AlgorithmOid.SHA512);
            case AlgorithmOid.ECDSA_SPECIFIED when asn is not null:
                return SpecifiedEcdsaParameters.Decode(asn.GetTagRawData()).HashAlgorithm;
            case AlgorithmOid.RSA_PSS when asn is not null:
                return decodeRsaPss(asn);
            default:
                throw new ArgumentException("Invalid signature algorithm");
        }
    }
    Oid decodeRsaPss(Asn1Reader asn) {
        var pssParams = RsaPssParameters.Decode(asn.GetTagRawData());
        sigParams = pssParams;
        return pssParams.HashAlgorithm;
    }
    void getConfiguration(Byte[] algIdBlob) {
        var asn = new Asn1Reader(algIdBlob);
        asn.MoveNext();
        Oid oid = new Asn1ObjectIdentifier(asn).Value;
        asn.MoveNext();
        hashAlgorithm = mapSignatureAlgorithmToHashAlgorithm(oid.Value!, asn);
    }

    /// <summary>
    /// Loads a private key pair that is associated with the signer certificate. The private key is acquired lazily on
    /// first signing operation. Derived classes can override this method to provide platform-specific key pairs
    /// (for example, CNG-based).
    /// </summary>
    /// <param name="certificate">Signer certificate.</param>
    /// <returns>
    /// Private key pair, or <strong>null</strong> if the certificate doesn't have an accessible private key.
    /// The signer takes ownership of the returned key pair.
    /// </returns>
    protected virtual AsymmetricKeyPair? AcquirePrivateKeyPair(X509Certificate2 certificate) {
        switch (keyType) {
            case KeyType.EcDsa:
                ECDsa? ecdsa = certificate.GetECDsaPrivateKey();
                return ecdsa is null ? null : new ECDsaPrivateKey(ecdsa);
            case KeyType.Rsa:
                RSA? rsa = certificate.GetRSAPrivateKey();
                return rsa is null ? null : new RsaPrivateKey(rsa);
            case KeyType.Dsa:
                // .NET Standard 2.0 doesn't have X509Certificate2.GetDSAPrivateKey() extension method.
                return certificate.PrivateKey is DSA dsa ? new DsaPrivateKey(dsa) : null;
            default:
                return null;
        }
    }
    void acquirePrivateKey() {
        // do not load private key again if it is already loaded
        if (privKeyPair is not null || SignerCertificate is null || !SignerCertificate.HasPrivateKey) {
            return;
        }
        privKeyPair = AcquirePrivateKeyPair(SignerCertificate);
    }
    AsymmetricKeyPair getSigningKey() {
        acquirePrivateKey();
        return privKeyPair ?? throw new InvalidOperationException("The signer doesn't have a private key.");
    }
    AsymmetricKeyPair getVerificationKey() {
        return pubKeyPair ?? throw new InvalidOperationException("The signer doesn't have a public key.");
    }
    // PSS is the only mode that carries additional signature parameters.
    ISignatureParameters? getSignatureParameters() {
        if (sigParams is not null) {
            return sigParams;
        }

        return keyType == KeyType.Rsa && paddingScheme == RSASignaturePadding.Pss
            ? new RsaPssParameters(hashAlgorithm, pssSaltByteCount)
            : null;
    }
    // ensures that parameters are applicable to the key algorithm
    void validateParameters(ISignatureParameters parameters) {
        Boolean valid = parameters switch {
            RsaPssParameters => keyType == KeyType.Rsa,
            SpecifiedEcdsaParameters => keyType == KeyType.EcDsa,
            _ => false
        };
        if (!valid) {
            throw new NotSupportedException($"Signature parameters of type '{parameters.GetType().Name}' are not applicable to the key algorithm.");
        }
    }

    // null-signed: the "signature" is a plain hash of data (see SignedContentBlob.Hash)
    static Boolean verifyNullSigned(Byte[] hash, Byte[] signature) {
        if (hash.Length != signature.Length) {
            return false;
        }

        // performs exact binary comparison
        return !hash.Where((t, index) => t != signature[index]).Any();
    }

    void getSignatureAlgorithm() {
        switch (keyType) {
            case KeyType.EcDsa:
                sigAlgorithm = sigParams is SpecifiedEcdsaParameters
                    ? new Oid(AlgorithmOid.ECDSA_SPECIFIED)                  // specifiedECDSA
                    : new Oid($"{hashAlgorithm.FriendlyName}ECDSA");          // ECDSA
                break;
            case KeyType.Rsa:
                sigAlgorithm = getSignatureParameters() is RsaPssParameters
                    ? new Oid(AlgorithmOid.RSA_PSS)                        // RSASSA-PSS
                    : new Oid($"{hashAlgorithm.FriendlyName}RSA");            // RSA
                break;
            case KeyType.Dsa:
                // DSA doesn't support PSS padding and hashing algorithm other than SHA1
                sigAlgorithm = new Oid(AlgorithmOid.SHA1_DSA);               // sha1DSA
                break;
            default:
                throw new NotSupportedException("Public key algorithm is not supported.");
        }
    }

    /// <summary>
    /// Signs the data with signer's private key and specified hash algorithm.
    /// </summary>
    /// <param name="message">Raw message to sign.</param>
    /// <exception cref="ArgumentNullException"><strong>message</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The signer doesn't have a private key.</exception>
    /// <exception cref="NotSupportedException">PSS salt length is not equal to the hash length.</exception>
    /// <returns>Raw signature.</returns>
    /// <remarks>For DSA private key only SHA1 hash is used.</remarks>
    public Byte[] SignData(Byte[] message) {
        if (message is null) {
            throw new ArgumentNullException(nameof(message));
        }

        Byte[] signature = getSigningKey().SignData(message, hashAlgorithm, getSignatureParameters());
        getSignatureAlgorithm();
        return signature;
    }
    /// <summary>
    /// Signs the hash with signer's private key.
    /// </summary>
    /// <param name="hash">Hash to sign.</param>
    /// <exception cref="ArgumentNullException"><strong>hash</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The signer doesn't have a private key.</exception>
    /// <exception cref="NotSupportedException">PSS salt length is not equal to the hash length.</exception>
    /// <returns>Raw signature.</returns>
    [Obsolete("Use SignData instead. Signing pre-computed hashes is not supported by all signature algorithms.")]
    public Byte[] SignHash(Byte[] hash) {
        if (hash is null) {
            throw new ArgumentNullException(nameof(hash));
        }

        Byte[] signature = getSigningKey().SignHash(hash, hashAlgorithm, getSignatureParameters());
        getSignatureAlgorithm();
        return signature;
    }
    /// <summary>
    /// Verifies that the specified signature matches the specified hash.
    /// </summary>
    /// <param name="message">The data that was signed.</param>
    /// <param name="signature">The signature data to be verified.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>message</strong> or <strong>signature</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">PSS salt length is not equal to the hash length.</exception>
    /// <returns>
    /// <strong>True</strong> if hash matches the one stored in signature, otherwise <strong>False</strong>.
    /// </returns>
    public Boolean VerifyData(Byte[] message, Byte[] signature) {
        if (message is null) {
            throw new ArgumentNullException(nameof(message));
        }
        if (signature is null) {
            throw new ArgumentNullException(nameof(signature));
        }

        if (nullSigned) {
            return verifyNullSigned(HashUtils.ComputeHash(hashAlgorithm, message), signature);
        }

        return getVerificationKey().VerifyData(message, signature, hashAlgorithm, getSignatureParameters());
    }
    /// <summary>
    /// Verifies that the specified signature matches the specified hash.
    /// </summary>
    /// <param name="hash">The hash value of the signed data.</param>
    /// <param name="signature">The signature data to be verified.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>hash</strong> or <strong>signature</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">PSS salt length is not equal to the hash length.</exception>
    /// <returns>
    /// <strong>True</strong> if hash matches the one stored in signature, otherwise <strong>False</strong>.
    /// </returns>
    [Obsolete("Use VerifyData instead. Verifying pre-computed hashes is not supported by all signature algorithms.")]
    public Boolean VerifyHash(Byte[] hash, Byte[] signature) {
        if (hash is null) {
            throw new ArgumentNullException(nameof(hash));
        }
        if (signature is null) {
            throw new ArgumentNullException(nameof(signature));
        }

        if (nullSigned) {
            return verifyNullSigned(hash, signature);
        }

        return getVerificationKey().VerifyHash(hash, signature, hashAlgorithm, getSignatureParameters());
    }
    /// <summary>
    /// Verifies signature of a signed blob by using specified public key.
    /// </summary>
    /// <param name="blob"></param>
    /// <param name="publicKey"></param>
    /// <returns></returns>
    /// <remarks>
    /// This method is suitable to validate certificate signing requests (CSR) or other data
    /// when signing key pair exist outside of X.509 certificate object.
    /// </remarks>
    public static Boolean VerifyData(SignedContentBlob blob, PublicKey publicKey) {
        if (blob is null) {
            throw new ArgumentNullException(nameof(blob));
        }
        if (publicKey is null) {
            throw new ArgumentNullException(nameof(publicKey));
        }

        if (blob.BlobType != ContentBlobType.SignedBlob) {
            throw new InvalidOperationException("The blob is not signed.");
        }

        using var signerInfo = new CryptSigner(publicKey.GetAsymmetricKeyPair(), null, true);
        signerInfo.getConfiguration(blob.SignatureAlgorithm.RawData);
        Byte[] signature = blob.Signature.GetValue().ToArray();
        if (!signerInfo.nullSigned) {
            signature = signerInfo.getVerificationKey().DecodeSignature(signature);
        }
        return signerInfo.VerifyData(blob.ToBeSignedData, signature);
    }
    /// <summary>
    /// Encodes a raw signature that was produced by <see cref="SignData"/> to the format that is stored
    /// in the signature field of signed structures.
    /// </summary>
    internal Byte[] EncodeSignature(Byte[] rawSignature) {
        return getVerificationKey().EncodeSignature(rawSignature);
    }

    /// <summary>
    /// Gets ASN-encoded algorithm identifier based on current configuration.
    /// </summary>
    /// <param name="alternate">
    /// Specifies whether alternate signature format is used. This parameter has meaning only for
    /// ECDSA keys. Otherwise, the parameter is ignored. Default value is <strong>false</strong>.
    /// </param>
    /// <returns>ASN-encoded algorithm identifier.</returns>
    [Obsolete("Use GetAlgorithmIdentifier() or GetAlgorithmIdentifier(ISignatureParameters) instead.")]
    public AlgorithmIdentifier GetAlgorithmIdentifier(Boolean alternate = false) {
        if (alternate && keyType == KeyType.EcDsa) {
            return new SpecifiedEcdsaParameters(hashAlgorithm).ToAlgorithmIdentifier();
        }

        return GetAlgorithmIdentifier();
    }
    /// <summary>
    /// Gets ASN-encoded algorithm identifier based on current configuration.
    /// </summary>
    /// <returns>ASN-encoded algorithm identifier.</returns>
    public AlgorithmIdentifier GetAlgorithmIdentifier() {
        return getAlgorithmIdentifier(getSignatureParameters());
    }
    /// <summary>
    /// Gets ASN-encoded algorithm identifier for the specified signature parameters. The signer configuration is not changed.
    /// </summary>
    /// <param name="parameters">
    /// Signature parameters. <strong>Null</strong> produces the default identifier for the key algorithm:
    /// PKCS#1 v1.5 for RSA, plain ECDSA, DSA.
    /// </param>
    /// <exception cref="NotSupportedException">The parameters are not applicable to the signer's key algorithm.</exception>
    /// <exception cref="ArgumentException">Hash algorithm of the parameters doesn't match the signer's hash algorithm.</exception>
    /// <returns>ASN-encoded algorithm identifier.</returns>
    public AlgorithmIdentifier GetAlgorithmIdentifier(ISignatureParameters? parameters) {
        if (parameters is not null) {
            validateParameters(parameters);
            if (parameters.HashAlgorithm.Value != hashAlgorithm.Value) {
                throw new ArgumentException("Hash algorithm of the parameters doesn't match the hash algorithm of the signer.", nameof(parameters));
            }
        }

        return getAlgorithmIdentifier(parameters);
    }
    AlgorithmIdentifier getAlgorithmIdentifier(ISignatureParameters? parameters) {
        if (parameters is not null) {
            return parameters.ToAlgorithmIdentifier();
        }
        if (sigAlgorithm is null) {
            getSignatureAlgorithm();
        }

        // PKCS#1 v1.5 padding: NULL parameters. Other algorithms don't have parameters.
        return keyType == KeyType.Rsa
            ? new AlgorithmIdentifier(sigAlgorithm!, new Asn1Null().GetRawDataAsMemory().ToArray())
            : new AlgorithmIdentifier(sigAlgorithm!, Array.Empty<Byte>());
    }

    #region IDisposable implementation
    void releaseUnmanagedResources() {
        // key pairs that were passed by caller are owned by the caller.
        if (ownsKeyPairs) {
            pubKeyPair?.Dispose();
        }
        // a private key pair that was derived from certificate is always owned by the signer.
        if (privKeyPair is not null && !ReferenceEquals(privKeyPair, pubKeyPair)) {
            privKeyPair.Dispose();
        }
        //TODO: Crypt32.CertFreeCertificateContext(SignerCertificate.Handle);
        SignerCertificate = null;
    }
    /// <inheritdoc />
    public void Dispose() {
        releaseUnmanagedResources();
        GC.SuppressFinalize(this);
    }
    /// <inheritdoc />
    ~CryptSigner() {
        releaseUnmanagedResources();
    }
    #endregion

    enum KeyType {
        EcDsa,
        Rsa,
        Dsa
    }
}
