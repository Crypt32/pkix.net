#nullable enable
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a cross-platform digital signature generator and validator.
/// </summary>
public class CryptSigner : ICryptSigner, IDisposable {
    const String DEFAULT_HASH_ALG = AlgorithmOid.SHA256;

    readonly Boolean ownsKeyPairs;
    AsymmetricKeyPair? pubKeyPair, privKeyPair;
    SignatureScheme scheme;
    KeyType keyType;

    /// <summary>
    /// Initializes a new instance of <strong>CryptSigner</strong> from an asymmetric key pair and optional
    /// hashing algorithm.
    /// </summary>
    /// <param name="keyPair">An asymmetric key instance.</param>
    /// <param name="hashingAlgorithm">
    /// Optional hashing algorithm. Default is <strong>SHA256</strong>. The default signature scheme of the key
    /// algorithm is used: PKCS#1 v1.5 for RSA, plain ECDSA and DSA. A signature algorithm identifier, such as
    /// <strong>sha256RSA</strong>, is accepted too: only its hash algorithm is used.
    /// </param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>keyPair</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     <strong>hashingAlgorithm</strong> is not a valid hash algorithm or signature algorithm identifier.
    /// </exception>
    /// <remarks>The signer doesn't take ownership of <strong>keyPair</strong>. The caller is responsible for disposing it.</remarks>
    public CryptSigner(AsymmetricKeyPair keyPair, Oid? hashingAlgorithm = null) {
        if (keyPair is null) {
            throw new ArgumentNullException(nameof(keyPair));
        }

        ownsKeyPairs = false;
        PublicKeyAlgorithm = setKeyPair(keyPair);
        scheme = keyPair.CreateSignatureScheme(resolveHashAlgorithm(hashingAlgorithm));
    }
    /// <summary>
    /// Initializes a new instance of <strong>CryptSigner</strong> from an asymmetric key pair and a signature scheme.
    /// </summary>
    /// <param name="keyPair">An asymmetric key instance.</param>
    /// <param name="signatureScheme">Signature scheme.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>keyPair</strong> or <strong>signatureScheme</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The scheme is not applicable to the key algorithm or is not based on a hash algorithm.
    /// </exception>
    /// <remarks>The signer doesn't take ownership of <strong>keyPair</strong>. The caller is responsible for disposing it.</remarks>
    public CryptSigner(AsymmetricKeyPair keyPair, SignatureScheme signatureScheme) {
        if (keyPair is null) {
            throw new ArgumentNullException(nameof(keyPair));
        }
        if (signatureScheme is null) {
            throw new ArgumentNullException(nameof(signatureScheme));
        }

        ownsKeyPairs = false;
        PublicKeyAlgorithm = setKeyPair(keyPair);
        scheme = validateScheme(signatureScheme);
    }
    /// <summary>
    /// Initializes a new instance of the <strong>CryptSigner</strong> class from signer certificate and
    /// client-provided hash algorithm.
    /// </summary>
    /// <param name="certificate">Signer certificate with associated private key.</param>
    /// <param name="hashingAlgorithm">
    /// Hash algorithm that is used to calculate the hash during signing or signature verification
    /// processes. Default is <strong>SHA256</strong>.
    /// </param>
    /// <exception cref="ArgumentException">
    ///     <strong>hashingAlgorithm</strong> parameter contains invalid hash algorithm identifier.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <strong>certificate</strong> parameter is null.
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
    public CryptSigner(X509Certificate2 certificate, Oid? hashingAlgorithm = null) {
        SignerCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        ownsKeyPairs = true;
        AsymmetricKeyPair keyPair = certificate.PublicKey.GetAsymmetricKeyPair();
        PublicKeyAlgorithm = setKeyPair(keyPair);
        scheme = keyPair.CreateSignatureScheme(resolveHashAlgorithm(hashingAlgorithm));
    }
    /// <summary>
    /// Initializes a new instance of the <strong>CryptSigner</strong> class from signer certificate and a signature scheme.
    /// </summary>
    /// <param name="certificate">Signer certificate with associated private key.</param>
    /// <param name="signatureScheme">Signature scheme.</param>
    /// <exception cref="ArgumentNullException">
    /// <strong>certificate</strong> or <strong>signatureScheme</strong> parameter is null.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// The scheme is not applicable to the key algorithm of the certificate or is not based on a hash algorithm.
    /// </exception>
    public CryptSigner(X509Certificate2 certificate, SignatureScheme signatureScheme) {
        if (signatureScheme is null) {
            throw new ArgumentNullException(nameof(signatureScheme));
        }
        SignerCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        ownsKeyPairs = true;
        PublicKeyAlgorithm = setKeyPair(certificate.PublicKey.GetAsymmetricKeyPair());
        scheme = validateScheme(signatureScheme);
    }

    /// <summary>
    /// Gets the certificate associated with the current instance of <strong>CryptSigner</strong>.
    /// </summary>
    public X509Certificate2? SignerCertificate { get; private set; }
    /// <summary>
    /// Gets public key algorithm.
    /// </summary>
    public Oid PublicKeyAlgorithm { get; }
    /// <summary>
    /// Gets or sets the hashing algorithm that is used to calculate the hash during signing or signature verification
    /// processes. Assigning a new value rebuilds the current <see cref="SignatureScheme"/> with the new hash algorithm
    /// and keeps its kind (classic, RSASSA-PSS, specifiedECDSA or NoSign).
    /// </summary>
    /// <exception cref="ArgumentNullException">The value is null.</exception>
    /// <exception cref="ArgumentException">The value is not a valid hash algorithm identifier.</exception>
    public Oid HashingAlgorithm {
        get => scheme.HashAlgorithm!;
        set {
            if (value is null) {
                throw new ArgumentNullException(nameof(value));
            }

            scheme = withHashAlgorithm(resolveHashAlgorithm(value));
        }
    }
    /// <summary>
    /// Gets resulting signature algorithm identifier.
    /// </summary>
    public Oid SignatureAlgorithm => scheme.AlgorithmId;
    /// <summary>
    /// Gets or sets signature padding scheme for RSA signature creation and validation.
    /// Default is <strong>PKCS1</strong>.
    /// </summary>
    /// <remarks>The property is ignored for non-RSA keys and for NoSign schemes.</remarks>
    [Obsolete("Use SignatureScheme property with SignatureScheme.CreatePss instead.")]
    public RSASignaturePadding PaddingScheme {
        get => scheme.Parameters is RsaPssParameters ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        set {
            if (value is null) {
                throw new ArgumentNullException(nameof(value));
            }
            if (keyType != KeyType.Rsa || scheme.IsNoSign) {
                return;
            }

            scheme = value == RSASignaturePadding.Pss
                ? SignatureScheme.CreatePss(HashingAlgorithm)
                : getVerificationKey().CreateSignatureScheme(HashingAlgorithm);
        }
    }
    /// <summary>
    /// Gets or sets the size, in bytes, of the random salt to use for the PSS padding.
    /// Default value matches the hash output length: 16 bytes for MD5, 20 bytes for SHA1, 32 bytes for
    /// SHA256, 48 bytes for SHA384 and 64 bytes for SHA512 hashing algorithm.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// The value is not equal to the hash length. The cross-platform implementation supports only this salt length.
    /// </exception>
    /// <remarks>The property is ignored for non-RSA keys. For non-RSA keys the getter returns zero.</remarks>
    [Obsolete("Use SignatureScheme property with SignatureScheme.CreatePss instead.")]
    public Int32 PssSaltByteCount {
        get {
            if (scheme.Parameters is RsaPssParameters pss) {
                return pss.SaltLength;
            }

            return keyType == KeyType.Rsa && !scheme.IsNoSign
                ? getHashLength(HashingAlgorithm.Value!)
                : 0;
        }
        set {
            if (keyType != KeyType.Rsa) {
                return;
            }
            if (value != getHashLength(HashingAlgorithm.Value!)) {
                throw new NotSupportedException("The cross-platform implementation supports only the PSS salt length that is equal to the hash length.");
            }
        }
    }
    /// <summary>
    /// Gets or sets the signature scheme of the signer. The scheme defines the hash algorithm of the signer.
    /// Assigning <strong>null</strong> resets the signer to the default scheme of the key algorithm with the current
    /// hash algorithm: PKCS#1 v1.5 for RSA, plain ECDSA, DSA.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// The scheme is not applicable to the signer's key algorithm or is not based on a hash algorithm.
    /// </exception>
    /// <remarks>
    /// NoSign schemes (<strong>sha256NoSign</strong> and so on) are accepted for any key. A signer with NoSign scheme
    /// can verify "signatures" (plain hashes) and cannot sign.
    /// </remarks>
    public SignatureScheme SignatureScheme {
        get => scheme;
        set => scheme = value is null
            ? getVerificationKey().CreateSignatureScheme(HashingAlgorithm)
            : validateScheme(value);
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
    SignatureScheme validateScheme(SignatureScheme value) {
        if (value.IsNoSign) {
            return value;
        }
        if (value.KeyAlgorithm?.Value != PublicKeyAlgorithm.Value) {
            throw new NotSupportedException($"The scheme '{value.AlgorithmId.Format(true)}' is not applicable to the signer's key algorithm.");
        }
        if (value.HashAlgorithm is null) {
            throw new NotSupportedException($"The scheme '{value.AlgorithmId.Format(true)}' is not based on a separate hash algorithm.");
        }

        return value;
    }
    // rebuilds the current scheme with another hash algorithm
    SignatureScheme withHashAlgorithm(Oid hashAlgorithm) {
        if (scheme.IsNoSign) {
            return SignatureScheme.CreateNoSign(hashAlgorithm);
        }

        return scheme.Parameters switch {
            RsaPssParameters => SignatureScheme.CreatePss(hashAlgorithm),
            SpecifiedEcdsaParameters => SignatureScheme.CreateSpecifiedEcdsa(hashAlgorithm),
            _ => getVerificationKey().CreateSignatureScheme(hashAlgorithm)
        };
    }
    // accepts hash algorithm identifier or signature algorithm identifier (only the hash algorithm is used).
    Oid resolveHashAlgorithm(Oid? value) {
        value ??= new Oid(DEFAULT_HASH_ALG);
        Oid hash;
        try {
            hash = Oid.FromOidValue(value.Value!, OidGroup.HashAlgorithm);
        } catch (CryptographicException) {
            hash = getHashOfSignatureAlgorithm(value);
        }

        // force SHA1 for DSA keys
        return keyType == KeyType.Dsa ? new Oid(AlgorithmOid.SHA1) : hash;
    }
    static Oid getHashOfSignatureAlgorithm(Oid signatureAlgorithm) {
        try {
            return SignatureScheme.Decode(new AlgorithmIdentifier(signatureAlgorithm, null)).HashAlgorithm
                   ?? throw new ArgumentException("Invalid signature algorithm");
        } catch (NotSupportedException ex) {
            throw new ArgumentException("Invalid signature algorithm", ex);
        }
    }
    static Int32 getHashLength(String hashOid) {
        return hashOid switch {
            AlgorithmOid.MD5    => 16,
            AlgorithmOid.SHA1   => 20,
            AlgorithmOid.SHA256 => 32,
            AlgorithmOid.SHA384 => 48,
            AlgorithmOid.SHA512 => 64,
            _                   => 0
        };
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
        if (scheme.IsNoSign) {
            throw new NotSupportedException($"The scheme '{scheme.AlgorithmId.Format(true)}' doesn't use a key, there is nothing to sign with.");
        }
        acquirePrivateKey();

        return privKeyPair ?? throw new InvalidOperationException("The signer doesn't have a private key.");
    }
    AsymmetricKeyPair getVerificationKey() {
        return pubKeyPair ?? throw new InvalidOperationException("The signer doesn't have a public key.");
    }

    // null-signed: the "signature" is a plain hash of data (see SignedContentBlob.Hash)
    static Boolean verifyNullSigned(Byte[] hash, Byte[] signature) {
        // performs exact binary comparison
        return hash.SequenceEqual(signature);
    }

    /// <summary>
    /// Signs the data with signer's private key and specified hash algorithm.
    /// </summary>
    /// <param name="message">Raw message to sign.</param>
    /// <exception cref="ArgumentNullException"><strong>message</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The signer doesn't have a private key.</exception>
    /// <exception cref="NotSupportedException">
    /// The signer uses NoSign scheme, or PSS salt length is not equal to the hash length.
    /// </exception>
    /// <returns>Raw signature.</returns>
    /// <remarks>For DSA private key only SHA1 hash is used.</remarks>
    public Byte[] SignData(Byte[] message) {
        if (message is null) {
            throw new ArgumentNullException(nameof(message));
        }

        return getSigningKey().SignData(message, scheme);
    }
    /// <summary>
    /// Signs the hash with signer's private key.
    /// </summary>
    /// <param name="hash">Hash to sign.</param>
    /// <exception cref="ArgumentNullException"><strong>hash</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The signer doesn't have a private key.</exception>
    /// <exception cref="NotSupportedException">
    /// The signer uses NoSign scheme, or PSS salt length is not equal to the hash length.
    /// </exception>
    /// <returns>Raw signature.</returns>
    [Obsolete("Use SignData instead. Signing pre-computed hashes is not supported by all signature algorithms.")]
    public Byte[] SignHash(Byte[] hash) {
        if (hash is null) {
            throw new ArgumentNullException(nameof(hash));
        }

        return getSigningKey().SignHash(hash, scheme);
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
        if (scheme.IsNoSign) {
            return verifyNullSigned(HashUtils.ComputeHash(scheme.HashAlgorithm!, message), signature);
        }

        return getVerificationKey().VerifyData(message, signature, scheme);
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
        if (scheme.IsNoSign) {
            return verifyNullSigned(hash, signature);
        }

        return getVerificationKey().VerifyHash(hash, signature, scheme);
    }
    /// <summary>
    /// Verifies signature of a signed blob by using specified public key.
    /// </summary>
    /// <param name="blob">Signed blob.</param>
    /// <param name="publicKey">Public key that is used to verify the signature.</param>
    /// <exception cref="ArgumentNullException"><strong>blob</strong> or <strong>publicKey</strong> parameter is null.</exception>
    /// <exception cref="InvalidOperationException">The blob is not signed.</exception>
    /// <exception cref="NotSupportedException">
    /// The signature algorithm of the blob is unknown or is not applicable to the public key.
    /// </exception>
    /// <returns>
    /// <strong>True</strong> if the signature is valid, otherwise <strong>False</strong>.
    /// </returns>
    /// <remarks>
    /// This method is suitable to validate certificate signing requests (CSR) or other data
    /// when signing key pair exist outside X.509 certificate object.
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

        SignatureScheme blobScheme = SignatureScheme.Decode(blob.SignatureAlgorithm);
        Byte[] signature = blob.Signature.GetValue().ToArray();
        if (blobScheme.IsNoSign) {
            return verifyNullSigned(HashUtils.ComputeHash(blobScheme.HashAlgorithm!, blob.ToBeSignedData), signature);
        }
        using AsymmetricKeyPair key = publicKey.GetAsymmetricKeyPair();

        return key.VerifyData(blob.ToBeSignedData, key.DecodeSignature(signature), blobScheme);
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
    [Obsolete("Use GetAlgorithmIdentifier() or SignatureScheme property instead.")]
    public AlgorithmIdentifier GetAlgorithmIdentifier(Boolean alternate = false) {
        if (alternate && keyType == KeyType.EcDsa) {
            return SignatureScheme.CreateSpecifiedEcdsa(HashingAlgorithm).ToAlgorithmIdentifier();
        }

        return GetAlgorithmIdentifier();
    }
    /// <summary>
    /// Gets ASN-encoded algorithm identifier based on current configuration.
    /// </summary>
    /// <returns>ASN-encoded algorithm identifier.</returns>
    public AlgorithmIdentifier GetAlgorithmIdentifier() {
        return scheme.ToAlgorithmIdentifier();
    }

    #region IDisposable implementation
    /// <summary>
    /// Releases the key pairs that are owned by the signer.
    /// </summary>
    /// <param name="disposing">Indicates whether the method is called from <see cref="Dispose()"/>.</param>
    protected virtual void Dispose(Boolean disposing) {
        if (!disposing) {
            return;
        }
        // key pairs that were passed by caller are owned by the caller.
        if (ownsKeyPairs) {
            pubKeyPair?.Dispose();
        }
        // a private key pair that was derived from certificate is always owned by the signer.
        if (privKeyPair is not null && !ReferenceEquals(privKeyPair, pubKeyPair)) {
            privKeyPair.Dispose();
        }
        SignerCertificate = null;
    }
    /// <inheritdoc />
    public void Dispose() {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
    #endregion

    enum KeyType {
        EcDsa,
        Rsa,
        Dsa
    }
}
