using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.Tests.Cryptography;

[TestClass]
public class KeyPairSignatureTests {
    static readonly Byte[] _data = [1, 2, 3, 4, 5, 6, 7, 8];
    static readonly Oid _sha256 = new(AlgorithmOid.SHA256);
    static readonly Oid _sha1 = new(AlgorithmOid.SHA1);
    static readonly Oid _sha384 = new(AlgorithmOid.SHA384);

    static ECDsa createEcdsa(String curve) {
        return ECDsa.Create(ECCurve.CreateFromFriendlyName(curve));
    }

    [TestMethod]
    [DataRow("nistP256", 256)]
    [DataRow("nistP384", 384)]
    [DataRow("nistP521", 521)]
    public void EcdsaSignVerifyAndWireFormat(String curve, Int32 keySize) {
        using ECDsa ecdsa = createEcdsa(curve);
        using var priv = new ECDsaPrivateKey(ecdsa);
        using var pub = new ECDsaPublicKey(ecdsa);
        Assert.AreEqual(keySize, priv.KeySize);

        Byte[] raw = priv.SignData(_data, _sha256);
        Assert.IsTrue(priv.VerifyData(_data, raw, _sha256));
        Assert.IsTrue(pub.VerifyData(_data, raw, _sha256));

        Byte[] encoded = priv.EncodeSignature(raw);
        // wire format is DER SEQUENCE of two INTEGERs
        Assert.IsTrue(ecdsa.VerifyData(_data, encoded, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        CollectionAssert.AreEqual(raw, pub.DecodeSignature(encoded));

        raw[0] ^= 0xff;
        Assert.IsFalse(pub.VerifyData(_data, raw, _sha256));
    }
    [TestMethod]
    public void EcdsaDecodePadsShortIntegers() {
        using ECDsa ecdsa = createEcdsa("nistP256");
        using var key = new ECDsaPublicKey(ecdsa);
        // r has leading zeros (shorter DER integer), s has high bit set (extra 0 in DER)
        var raw = new Byte[64];
        raw[2] = 0x11;
        raw[31] = 0x22;
        raw[32] = 0x80;
        raw[63] = 0x33;
        Byte[] encoded = key.EncodeSignature(raw);
        CollectionAssert.AreEqual(raw, key.DecodeSignature(encoded));
    }
    [TestMethod]
    public void PublicOnlyKeyCannotSign() {
        using ECDsa ecdsa = createEcdsa("nistP256");
        using var pub = new ECDsaPublicKey(ecdsa);
        Assert.IsTrue(pub.PublicOnly);
        Assert.ThrowsExactly<InvalidOperationException>(() => pub.SignData(_data, _sha256));
    }
    [TestMethod]
    public void EcdsaAcceptsSpecifiedParametersOnlyWithSameHash() {
        using ECDsa ecdsa = createEcdsa("nistP256");
        using var key = new ECDsaPrivateKey(ecdsa);
        Byte[] raw = key.SignData(_data, _sha256, new SpecifiedEcdsaParameters(_sha256));
        Assert.IsTrue(key.VerifyData(_data, raw, _sha256, new SpecifiedEcdsaParameters(_sha256)));
        Assert.ThrowsExactly<NotSupportedException>(() => key.SignData(_data, _sha256, new SpecifiedEcdsaParameters(_sha1)));
        Assert.ThrowsExactly<NotSupportedException>(() => key.SignData(_data, _sha256, RsaPssParameters.CreateDefault(_sha256)));
    }

    [TestMethod]
    public void RsaPkcs1SignVerify() {
        using RSA rsa = RSA.Create(2048);
        using var priv = new RsaPrivateKey(rsa);
        using var pub = new RsaPublicKey(rsa);
        Assert.AreEqual(2048, priv.KeySize);
        Assert.AreEqual(2048, pub.KeySize);

        Byte[] sig = priv.SignData(_data, _sha256);
        Assert.IsTrue(pub.VerifyData(_data, sig, _sha256));
        Assert.IsTrue(rsa.VerifyData(_data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        // RSA signature is stored as is
        CollectionAssert.AreEqual(sig, priv.EncodeSignature(sig));
        CollectionAssert.AreEqual(sig, priv.DecodeSignature(sig));
        sig[0] ^= 0xff;
        Assert.IsFalse(pub.VerifyData(_data, sig, _sha256));
    }
    [TestMethod]
    public void RsaPssUsesHashLengthSalt() {
        using RSA rsa = RSA.Create(2048);
        using var key = new RsaPrivateKey(rsa);
        var pss = RsaPssParameters.CreateDefault(_sha256);
        Byte[] sig = key.SignData(_data, _sha256, pss);
        Assert.IsTrue(key.VerifyData(_data, sig, _sha256, pss));
        Assert.IsTrue(rsa.VerifyData(_data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        // PSS signature is not valid as PKCS#1 signature
        Assert.IsFalse(key.VerifyData(_data, sig, _sha256));
    }
    [TestMethod]
    public void RsaPssRejectsNonDefaultSaltAndMismatchedHash() {
        using RSA rsa = RSA.Create(2048);
        using var key = new RsaPrivateKey(rsa);
        Assert.ThrowsExactly<NotSupportedException>(() => key.SignData(_data, _sha256, new RsaPssParameters(_sha256, 20)));
        Assert.ThrowsExactly<NotSupportedException>(() => key.VerifyData(_data, new Byte[256], _sha256, new RsaPssParameters(_sha256, 0)));
        Assert.ThrowsExactly<NotSupportedException>(() => key.SignData(_data, _sha256, new RsaPssParameters(_sha1, 20)));
        Assert.ThrowsExactly<NotSupportedException>(() => key.SignData(_data, _sha256, new SpecifiedEcdsaParameters(_sha256)));
    }

    [TestMethod]
    public void DsaSignVerifyAndWireFormat() {
        using DSA dsa = DSA.Create(1024);
        using var priv = new DsaPrivateKey(dsa);
        using var pub = new DsaPublicKey(dsa);
        Assert.AreEqual(1024, priv.KeySize);

        Byte[] raw = priv.SignData(_data, _sha1);
        Assert.AreEqual(40, raw.Length);
        Assert.IsTrue(pub.VerifyData(_data, raw, _sha1));
        Byte[] encoded = priv.EncodeSignature(raw);
        Assert.IsTrue(dsa.VerifyData(_data, encoded, HashAlgorithmName.SHA1, DSASignatureFormat.Rfc3279DerSequence));
        CollectionAssert.AreEqual(raw, pub.DecodeSignature(encoded));
        Assert.ThrowsExactly<NotSupportedException>(() => priv.SignData(_data, _sha1, RsaPssParameters.CreateDefault(_sha1)));
    }

    [TestMethod]
    public void SignHashAndSignDataAreConsistent() {
        using RSA rsa = RSA.Create(2048);
        using var key = new RsaPrivateKey(rsa);
        Byte[] hash = SHA256.Create().ComputeHash(_data);
        Byte[] sig = key.SignHash(hash, _sha256);
        Assert.IsTrue(key.VerifyData(_data, sig, _sha256));
        Assert.IsTrue(key.VerifyHash(hash, sig, _sha256));
    }

    [TestMethod]
    public void CryptSignerWithKeyPairDoesNotDisposeCallerKey() {
        using ECDsa ecdsa = createEcdsa("nistP256");
        using var key = new ECDsaPrivateKey(ecdsa);
        using (var signer = new CryptSigner(key, _sha256)) {
            Byte[] sig = signer.SignData(_data);
            Assert.IsTrue(signer.VerifyData(_data, sig));
        }
        // the key pair remains usable after signer is disposed
        Byte[] sig2 = key.SignData(_data, _sha256);
        Assert.IsTrue(key.VerifyData(_data, sig2, _sha256));
    }
    [TestMethod]
    public void CryptSignerWithPublicKeyCannotSign() {
        using ECDsa ecdsa = createEcdsa("nistP256");
        using var pub = new ECDsaPublicKey(ecdsa);
        using var signer = new CryptSigner(pub, _sha256);
        Assert.ThrowsExactly<InvalidOperationException>(() => signer.SignData(_data));
    }
    [TestMethod]
    public void CryptSignerPssWithNonDefaultSaltIsNotSupported() {
        using RSA rsa = RSA.Create(2048);
        using var key = new RsaPrivateKey(rsa);
        using var signer = new CryptSigner(key, _sha256) {
            SignatureParameters = new RsaPssParameters(_sha256, 20)
        };
        Assert.ThrowsExactly<NotSupportedException>(() => signer.SignData(_data));
    }
    [TestMethod]
    public void CryptSignerSignatureParametersDriveAlgorithmIdentifier() {
        using RSA rsa = RSA.Create(2048);
        using var key = new RsaPrivateKey(rsa);
        using var signer = new CryptSigner(key, _sha256);
        Assert.AreEqual(AlgorithmOid.SHA256_RSA, signer.GetAlgorithmIdentifier().AlgorithmId.Value);

        signer.SignatureParameters = RsaPssParameters.CreateDefault(_sha384);
        Assert.AreEqual(AlgorithmOid.SHA384, signer.HashingAlgorithm.Value);
        Assert.AreEqual(AlgorithmOid.RSA_PSS, signer.GetAlgorithmIdentifier().AlgorithmId.Value);
        Byte[] sig = signer.SignData(_data);
        Assert.AreEqual(AlgorithmOid.RSA_PSS, signer.SignatureAlgorithm.Value);
        Assert.IsTrue(signer.VerifyData(_data, sig));
        Assert.ThrowsExactly<InvalidOperationException>(() => signer.HashingAlgorithm = _sha256);

        signer.SignatureParameters = null;
        Assert.IsNull(signer.SignatureParameters);
        Assert.AreEqual(AlgorithmOid.SHA384_RSA, signer.GetAlgorithmIdentifier().AlgorithmId.Value);
    }
    [TestMethod]
    public void CryptSignerRejectsIncompatibleSignatureParameters() {
        using ECDsa ecdsa = createEcdsa("nistP256");
        using var key = new ECDsaPrivateKey(ecdsa);
        using var signer = new CryptSigner(key, _sha256);
        Assert.ThrowsExactly<NotSupportedException>(() => signer.SignatureParameters = RsaPssParameters.CreateDefault(_sha256));
        Assert.ThrowsExactly<ArgumentException>(() => signer.GetAlgorithmIdentifier(new SpecifiedEcdsaParameters(_sha1)));
        Assert.AreEqual(AlgorithmOid.ECDSA_SPECIFIED, signer.GetAlgorithmIdentifier(new SpecifiedEcdsaParameters(_sha256)).AlgorithmId.Value);
        // identifier overload doesn't change the signer
        Assert.AreEqual(AlgorithmOid.SHA256_ECDSA, signer.GetAlgorithmIdentifier().AlgorithmId.Value);

        signer.SignatureParameters = new SpecifiedEcdsaParameters(_sha256);
        Byte[] sig = signer.SignData(_data);
        Assert.IsTrue(signer.VerifyData(_data, sig));
        Assert.AreEqual(AlgorithmOid.ECDSA_SPECIFIED, signer.GetAlgorithmIdentifier().AlgorithmId.Value);
    }
    sealed class TrackingSigner(X509Certificate2 certificate, Oid hash) : CryptSigner(certificate, hash) {
        public Int32 AcquireCount { get; private set; }
        protected override AsymmetricKeyPair? AcquirePrivateKeyPair(X509Certificate2 certificate) {
            AcquireCount++;
            return base.AcquirePrivateKeyPair(certificate);
        }
    }
    [TestMethod]
    public void CryptSignerAcquiresPrivateKeyLazilyThroughOverride() {
        using ECDsa ecdsa = createEcdsa("nistP256");
        var req = new CertificateRequest("CN=test", ecdsa, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var signer = new TrackingSigner(cert, _sha256);
        Assert.AreEqual(0, signer.AcquireCount);
        Byte[] sig = signer.SignData(_data);
        signer.SignData(_data);
        Assert.AreEqual(1, signer.AcquireCount);
        Assert.IsTrue(signer.VerifyData(_data, sig));
    }
    [TestMethod]
    public void SignedBlobRoundTripsForEcdsaAndRsa() {
        using ECDsa ecdsa = createEcdsa("nistP384");
        using var ecKey = new ECDsaPrivateKey(ecdsa);
        using RSA rsa = RSA.Create(2048);
        using var rsaKey = new RsaPrivateKey(rsa);
        foreach (AsymmetricKeyPair key in new AsymmetricKeyPair[] { ecKey, rsaKey }) {
            using var signer = new CryptSigner(key, _sha256);
            var blob = new SignedContentBlob([0x30, 0x03, 0x02, 0x01, 0x05], ContentBlobType.ToBeSignedBlob);
            blob.Sign(signer);
            Byte[] encoded = blob.Encode();
            var parsed = new SignedContentBlob(encoded, ContentBlobType.SignedBlob);
            Byte[] signature = key.DecodeSignature(parsed.Signature.GetValue().ToArray());
            Assert.IsTrue(key.VerifyData(parsed.ToBeSignedData, signature, _sha256));
        }
    }
}
