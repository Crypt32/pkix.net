using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.Tests.Cryptography;

[TestClass]
public class SignatureSchemeTests {
    static readonly Byte[] _data = [1, 2, 3, 4, 5, 6, 7, 8];
    static readonly Oid _rsa = new(AlgorithmOid.RSA);
    static readonly Oid _ecc = new(AlgorithmOid.ECC);
    static readonly Oid _dsa = new(AlgorithmOid.DSA);
    static readonly Oid _sha1 = new(AlgorithmOid.SHA1);
    static readonly Oid _sha256 = new(AlgorithmOid.SHA256);
    static readonly Oid _sha384 = new(AlgorithmOid.SHA384);
    static readonly Oid _sha512 = new(AlgorithmOid.SHA512);

    static SignatureScheme roundTrip(SignatureScheme scheme) {
        AlgorithmIdentifier algId = scheme.ToAlgorithmIdentifier();
        SignatureScheme decoded = SignatureScheme.Decode(algId.RawData);
        Assert.AreEqual(scheme, decoded);
        CollectionAssert.AreEqual(algId.RawData, decoded.ToAlgorithmIdentifier().RawData);
        return decoded;
    }

    [TestMethod]
    [DataRow(AlgorithmOid.RSA, AlgorithmOid.MD5, "md5RSA")]
    [DataRow(AlgorithmOid.RSA, AlgorithmOid.SHA1, "sha1RSA")]
    [DataRow(AlgorithmOid.RSA, AlgorithmOid.SHA256, "sha256RSA")]
    [DataRow(AlgorithmOid.RSA, AlgorithmOid.SHA384, "sha384RSA")]
    [DataRow(AlgorithmOid.RSA, AlgorithmOid.SHA512, "sha512RSA")]
    [DataRow(AlgorithmOid.ECC, AlgorithmOid.SHA1, "sha1ECDSA")]
    [DataRow(AlgorithmOid.ECC, AlgorithmOid.SHA256, "sha256ECDSA")]
    [DataRow(AlgorithmOid.ECC, AlgorithmOid.SHA384, "sha384ECDSA")]
    [DataRow(AlgorithmOid.ECC, AlgorithmOid.SHA512, "sha512ECDSA")]
    [DataRow(AlgorithmOid.DSA, AlgorithmOid.SHA1, "sha1DSA")]
    public void ClassicSchemesRoundTrip(String keyAlgorithm, String hash, String name) {
        SignatureScheme scheme = SignatureScheme.CreateClassic(new Oid(keyAlgorithm), new Oid(hash));
        Assert.AreEqual(name, scheme.AlgorithmId.FriendlyName);
        Assert.AreEqual(name, scheme.AlgorithmId.FriendlyName);
        Assert.AreEqual(keyAlgorithm, scheme.KeyAlgorithm!.Value);
        Assert.AreEqual(hash, scheme.HashAlgorithm!.Value);
        Assert.IsFalse(scheme.IsNoSign);
        Assert.IsFalse(scheme.IsComposite);

        // RSA identifiers have NULL parameters, ECDSA and DSA don't have them
        AlgorithmIdentifier algId = scheme.ToAlgorithmIdentifier();
        if (keyAlgorithm == AlgorithmOid.RSA) {
            CollectionAssert.AreEqual(new Byte[] { 5, 0 }, algId.Parameters);
        } else {
            Assert.IsNull(algId.Parameters);
        }
        SignatureScheme decoded = roundTrip(scheme);
        Assert.AreEqual(hash, decoded.HashAlgorithm!.Value);
    }
    [TestMethod]
    public void ClassicSchemeRejectsInvalidCombinations() {
        Assert.ThrowsExactly<NotSupportedException>(() => SignatureScheme.CreateClassic(_dsa, _sha256));
        Assert.ThrowsExactly<NotSupportedException>(() => SignatureScheme.CreateClassic(_ecc, new Oid(AlgorithmOid.MD5)));
        Assert.ThrowsExactly<NotSupportedException>(() => SignatureScheme.CreateClassic(new Oid(AlgorithmOid.ML_DSA_44), _sha256));
    }
    [TestMethod]
    public void DecodeToleratesNullParametersOnEcdsa() {
        var algId = new AlgorithmIdentifier(new Oid(AlgorithmOid.SHA256_ECDSA), []);
        SignatureScheme scheme = SignatureScheme.Decode(algId);
        Assert.AreEqual("sha256ECDSA", scheme.AlgorithmId.FriendlyName);
        // we always produce the canonical encoding
        Assert.IsNull(scheme.ToAlgorithmIdentifier().Parameters);
    }
    [TestMethod]
    public void PssAndSpecifiedEcdsaSchemesRoundTrip() {
        SignatureScheme pss = SignatureScheme.CreatePss(_sha384);
        Assert.AreEqual(AlgorithmOid.RSA_PSS, pss.AlgorithmId.Value);
        Assert.AreEqual(AlgorithmOid.RSA, pss.KeyAlgorithm!.Value);
        Assert.IsInstanceOfType<RsaPssParameters>(pss.Parameters);
        Assert.AreEqual(48, ((RsaPssParameters)pss.Parameters!).SaltLength);
        Assert.AreEqual(AlgorithmOid.SHA384, roundTrip(pss).HashAlgorithm!.Value);

        SignatureScheme specified = SignatureScheme.CreateSpecifiedEcdsa(_sha256);
        Assert.AreEqual(AlgorithmOid.ECDSA_SPECIFIED, specified.AlgorithmId.Value);
        Assert.AreEqual(AlgorithmOid.ECC, specified.KeyAlgorithm!.Value);
        Assert.AreEqual(AlgorithmOid.SHA256, roundTrip(specified).HashAlgorithm!.Value);

        Assert.AreNotEqual(pss, SignatureScheme.CreatePss(_sha256));
        Assert.AreEqual(SignatureScheme.CreatePss(_sha256), SignatureScheme.CreatePss(_sha256));
        Assert.ThrowsExactly<ArgumentException>(() => SignatureScheme.Decode(new AlgorithmIdentifier(new Oid(AlgorithmOid.RSA_PSS), null)));
    }

    [TestMethod]
    [DataRow(AlgorithmOid.MD5, "md5NoSign")]
    [DataRow(AlgorithmOid.SHA1, "sha1NoSign")]
    [DataRow(AlgorithmOid.SHA256, "sha256NoSign")]
    [DataRow(AlgorithmOid.SHA384, "sha384NoSign")]
    [DataRow(AlgorithmOid.SHA512, "sha512NoSign")]
    public void NoSignSchemesAreDecodedFromHashOidInSignaturePosition(String hash, String name) {
        SignatureScheme scheme = SignatureScheme.CreateNoSign(new Oid(hash));
        Assert.IsTrue(scheme.IsNoSign);
        Assert.AreEqual(name, scheme.AlgorithmId.FriendlyName);
        // the OID value is the same as of the hash algorithm, but the friendly name is the signature one.
        Assert.AreEqual(hash, scheme.AlgorithmId.Value);
        Assert.AreEqual(name, scheme.AlgorithmId.FriendlyName);
        Assert.IsNull(scheme.KeyAlgorithm);
        Assert.AreEqual(hash, scheme.HashAlgorithm!.Value);
        CollectionAssert.AreEqual(new Byte[] { 5, 0 }, scheme.ToAlgorithmIdentifier().Parameters);

        SignatureScheme decoded = roundTrip(scheme);
        Assert.IsTrue(decoded.IsNoSign);
        // absent parameters are accepted too
        Assert.IsTrue(SignatureScheme.Decode(new AlgorithmIdentifier(new Oid(hash), null)).IsNoSign);
        Assert.AreNotEqual(scheme, SignatureScheme.CreateClassic(_rsa, new Oid(AlgorithmOid.SHA256)));
    }
    [TestMethod]
    public void NoSignSchemeIsNotApplicableToKeyPairs() {
        using RSA rsa = RSA.Create(2048);
        using var key = new RsaPrivateKey(rsa);
        SignatureScheme noSign = SignatureScheme.CreateNoSign(_sha256);
        Assert.ThrowsExactly<NotSupportedException>(() => key.SignData(_data, noSign));
        Assert.ThrowsExactly<NotSupportedException>(() => key.VerifyData(_data, new Byte[256], noSign));
        Assert.ThrowsExactly<NotSupportedException>(() => SignatureScheme.CreateNoSign(new Oid(AlgorithmOid.ML_DSA_65)));
    }

    [TestMethod]
    public void PureSchemesHaveNoParametersAndNoHash() {
        Oid[] oids = getPureOids().Select(x => new Oid(x)).ToArray();
        // 3 ML-DSA + 12 SLH-DSA
        Assert.HasCount(15, oids);
        foreach (Oid oid in oids) {
            SignatureScheme scheme = SignatureScheme.CreateFromOid(oid);
            Assert.IsNull(scheme.Parameters);
            Assert.IsNull(scheme.HashAlgorithm);
            Assert.AreEqual(oid.Value, scheme.KeyAlgorithm!.Value);
            Assert.IsNull(scheme.ToAlgorithmIdentifier().Parameters);
            roundTrip(scheme);
            // the parameters field must be absent
            Assert.ThrowsExactly<ArgumentException>(() => SignatureScheme.Decode(new AlgorithmIdentifier(oid, [])));
        }
        Assert.AreEqual("ML-DSA-65", SignatureScheme.CreateFromOid(new Oid(AlgorithmOid.ML_DSA_65)).AlgorithmId.FriendlyName);
    }
    static String[] getPureOids() {
        return [
            AlgorithmOid.ML_DSA_44, AlgorithmOid.ML_DSA_65, AlgorithmOid.ML_DSA_87,
            AlgorithmOid.SLH_DSA_SHA2_128S, AlgorithmOid.SLH_DSA_SHA2_128F, AlgorithmOid.SLH_DSA_SHA2_192S, AlgorithmOid.SLH_DSA_SHA2_192F,
            AlgorithmOid.SLH_DSA_SHA2_256S, AlgorithmOid.SLH_DSA_SHA2_256F, AlgorithmOid.SLH_DSA_SHAKE_128S, AlgorithmOid.SLH_DSA_SHAKE_128F,
            AlgorithmOid.SLH_DSA_SHAKE_192S, AlgorithmOid.SLH_DSA_SHAKE_192F, AlgorithmOid.SLH_DSA_SHAKE_256S, AlgorithmOid.SLH_DSA_SHAKE_256F
        ];
    }
    [TestMethod]
    public void UnknownAlgorithmIsNotSupported() {
        Assert.ThrowsExactly<NotSupportedException>(() => SignatureScheme.Decode(new AlgorithmIdentifier(new Oid("1.2.3.4.5"), null)));
        Assert.ThrowsExactly<NotSupportedException>(() => SignatureScheme.CreateFromOid(new Oid("1.2.3.4.5")));
    }

    [TestMethod]
    public void AllCompositeSchemesAreKnown() {
        var names = new System.Collections.Generic.HashSet<String>();
        // Edwards curve variants (39, 48, 51) are not supported
        foreach (Int32 suffix in Enumerable.Range(37, 18).Except([39, 48, 51])) {
            var oid = new Oid("1.3.6.1.5.5.7.6." + suffix);
            SignatureScheme scheme = SignatureScheme.CreateFromOid(oid);
            Assert.IsTrue(scheme.IsComposite);
            // one OID for key and signature, no parameters
            Assert.AreEqual(oid.Value, scheme.KeyAlgorithm!.Value);
            Assert.IsNull(scheme.ToAlgorithmIdentifier().Parameters);
            var composite = (CompositeSignatureSchemeParams)scheme.Parameters!;
            // the draft name is a protocol constant, the system OID database may name these OIDs differently
            Assert.IsTrue(names.Add(composite.Name));
            Assert.AreEqual("COMPSIG-" + composite.Name, composite.Label);
            Assert.IsTrue(composite.Name.StartsWith("MLDSA"));
            Assert.IsFalse(composite.TraditionalScheme.IsComposite);
            Assert.IsFalse(composite.TraditionalScheme.IsNoSign);
            // RSA components define the key size, EC components define the curve
            Assert.AreEqual(composite.TraditionalScheme.KeyAlgorithm?.Value == AlgorithmOid.RSA, composite.TraditionalRsaKeySize > 0);
            Assert.AreEqual(composite.TraditionalScheme.KeyAlgorithm?.Value == AlgorithmOid.ECC, composite.TraditionalCurve is not null);
            Assert.AreEqual(composite.HashAlgorithm.Value, scheme.HashAlgorithm!.Value);
            roundTrip(scheme);
        }
        Assert.HasCount(15, names);
        Assert.ThrowsExactly<NotSupportedException>(() => SignatureScheme.CreateFromOid(new Oid("1.3.6.1.5.5.7.6.55")));
        Assert.ThrowsExactly<ArgumentException>(() => SignatureScheme.Decode(new AlgorithmIdentifier(new Oid("1.3.6.1.5.5.7.6.45"), [])));
    }
    [TestMethod]
    public void CompositeSchemeDescribesBothComponents() {
        SignatureScheme scheme = SignatureScheme.CreateFromOid(new Oid("1.3.6.1.5.5.7.6.45"));
        var composite = (CompositeSignatureSchemeParams)scheme.Parameters!;
        Assert.AreEqual("MLDSA65-ECDSA-P256-SHA512", composite.Name);
        Assert.AreEqual("COMPSIG-MLDSA65-ECDSA-P256-SHA512", composite.Label);
        Assert.AreEqual(AlgorithmOid.ML_DSA_65, composite.MLDsaAlgorithm.Value);
        Assert.AreEqual(AlgorithmOid.SHA512, scheme.HashAlgorithm!.Value);
        Assert.AreEqual(AlgorithmOid.ECDSA_P256, composite.TraditionalCurve!.Value);
        // the traditional component is a regular scheme with its own hash
        Assert.AreEqual(AlgorithmOid.SHA256_ECDSA, composite.TraditionalScheme.AlgorithmId.Value);
        Assert.AreEqual(AlgorithmOid.SHA256, composite.TraditionalScheme.HashAlgorithm!.Value);

        SignatureScheme rsa = SignatureScheme.CreateFromOid(new Oid("1.3.6.1.5.5.7.6.43"));
        var rsaParams = (CompositeSignatureSchemeParams)rsa.Parameters!;
        Assert.AreEqual(4096, rsaParams.TraditionalRsaKeySize);
        Assert.AreEqual(AlgorithmOid.RSA_PSS, rsaParams.TraditionalScheme.AlgorithmId.Value);
        Assert.AreEqual(AlgorithmOid.SHA384, rsaParams.TraditionalScheme.HashAlgorithm!.Value);
        Assert.AreEqual(48, ((RsaPssParameters)rsaParams.TraditionalScheme.Parameters!).SaltLength);
    }
    [TestMethod]
    public void CompositeMessageRepresentativeHasExpectedStructure() {
        var composite = (CompositeSignatureSchemeParams)SignatureScheme.CreateFromOid(new Oid("1.3.6.1.5.5.7.6.45")).Parameters!;
        Byte[] ctx = [9, 9, 9];
        Byte[] m = composite.CreateMessageRepresentative(_data, ctx);
        Byte[] prefix = CompositeSignatureSchemeParams.GetPrefix();
        Byte[] label = System.Text.Encoding.ASCII.GetBytes(composite.Label);
        Assert.AreEqual(32, prefix.Length);
        Assert.AreEqual(prefix.Length + label.Length + 1 + ctx.Length + 64, m.Length);
        CollectionAssert.AreEqual(prefix, m.Take(32).ToArray());
        CollectionAssert.AreEqual(label, m.Skip(32).Take(label.Length).ToArray());
        Assert.AreEqual(3, m[32 + label.Length]);
        CollectionAssert.AreEqual(ctx, m.Skip(32 + label.Length + 1).Take(3).ToArray());
        CollectionAssert.AreEqual(SHA512.Create().ComputeHash(_data), m.Skip(m.Length - 64).ToArray());

        Assert.ThrowsExactly<ArgumentException>(() => composite.CreateMessageRepresentative(_data, new Byte[256]));
    }

    [TestMethod]
    public void KeyPairsCreateSupportedSchemes() {
        using RSA rsa = RSA.Create(2048);
        using var rsaKey = new RsaPrivateKey(rsa);
        Assert.AreEqual("sha256RSA", rsaKey.CreateSignatureScheme().AlgorithmId.FriendlyName);
        Assert.AreEqual("sha512RSA", rsaKey.CreateSignatureScheme(_sha512).AlgorithmId.FriendlyName);
        Assert.AreEqual("RSASSA-PSS", rsaKey.CreateSignatureScheme(_sha384, true).AlgorithmId.FriendlyName);

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ecKey = new ECDsaPrivateKey(ecdsa);
        Assert.AreEqual("sha256ECDSA", ecKey.CreateSignatureScheme().AlgorithmId.FriendlyName);
        Assert.AreEqual("specifiedECDSA", ecKey.CreateSignatureScheme(null, true).AlgorithmId.FriendlyName);
        Assert.AreEqual(AlgorithmOid.ECDSA_SPECIFIED, ecKey.CreateSignatureScheme(_sha384, true).AlgorithmId.Value);

        using DSA dsa = DSA.Create(1024);
        using var dsaKey = new DsaPrivateKey(dsa);
        Assert.AreEqual("sha1DSA", dsaKey.CreateSignatureScheme().AlgorithmId.FriendlyName);
        Assert.ThrowsExactly<NotSupportedException>(() => dsaKey.CreateSignatureScheme(_sha256));
        // DSA has no alternate format
        Assert.ThrowsExactly<NotSupportedException>(() => dsaKey.CreateSignatureScheme(null, true));
    }
    [TestMethod]
    public void KeyPairsSignAndVerifyWithSchemes() {
        using RSA rsa = RSA.Create(2048);
        using var rsaKey = new RsaPrivateKey(rsa);
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var ecKey = new ECDsaPrivateKey(ecdsa);
        using DSA dsa = DSA.Create(1024);
        using var dsaKey = new DsaPrivateKey(dsa);

        foreach (AsymmetricKeyPair key in new AsymmetricKeyPair[] { rsaKey, ecKey, dsaKey }) {
            SignatureScheme scheme = key.CreateSignatureScheme();
            Byte[] sig = key.SignData(_data, scheme);
            Assert.IsTrue(key.VerifyData(_data, sig, scheme));
            sig[0] ^= 0xff;
            Assert.IsFalse(key.VerifyData(_data, sig, scheme));
        }

        SignatureScheme pss = rsaKey.CreateSignatureScheme(_sha256, true);
        Byte[] pssSig = rsaKey.SignData(_data, pss);
        Assert.IsTrue(rsaKey.VerifyData(_data, pssSig, pss));
        Assert.IsFalse(rsaKey.VerifyData(_data, pssSig, rsaKey.CreateSignatureScheme(_sha256)));

        SignatureScheme specified = ecKey.CreateSignatureScheme(_sha384, true);
        Assert.IsTrue(ecKey.VerifyData(_data, ecKey.SignData(_data, specified), specified));
    }
    [TestMethod]
    public void KeyPairsRejectForeignAndUnimplementedSchemes() {
        using RSA rsa = RSA.Create(2048);
        using var rsaKey = new RsaPrivateKey(rsa);
        using var rsaPub = new RsaPublicKey(rsa);
        // scheme of another key algorithm
        Assert.ThrowsExactly<NotSupportedException>(() => rsaKey.SignData(_data, SignatureScheme.CreateClassic(_ecc, _sha256)));
        Assert.ThrowsExactly<NotSupportedException>(() => rsaPub.VerifyData(_data, [], SignatureScheme.CreateClassic(_dsa, _sha1)));
        // schemes that are not implemented by RSA/ECDSA/DSA key pairs yet
        Assert.ThrowsExactly<NotSupportedException>(() => rsaKey.SignData(_data, SignatureScheme.CreateFromOid(new Oid(AlgorithmOid.ML_DSA_65))));
        Assert.ThrowsExactly<NotSupportedException>(() => rsaKey.SignData(_data, SignatureScheme.CreateFromOid(new Oid("1.3.6.1.5.5.7.6.42"))));
        // public key cannot sign
        Assert.ThrowsExactly<InvalidOperationException>(() => rsaPub.SignData(_data, rsaPub.CreateSignatureScheme()));
    }

    sealed record SignedCase(SignedContentBlob Blob, AsymmetricKeyPair Key, String SchemeName);
    static SignedContentBlob createBlob(X509Certificate2 cert) {
        return new SignedContentBlob(cert.RawData, ContentBlobType.SignedBlob);
    }
    static X509Certificate2 createSelfSigned(CertificateRequest request) {
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
    [TestMethod]
    public void EdwardsCurveAlgorithmsAreNotSupported() {
        // Ed25519, Ed448 and composites that use them are not supported by Windows CNG
        foreach (String oid in new[] { "1.3.101.112", "1.3.101.113", "1.3.6.1.5.5.7.6.39", "1.3.6.1.5.5.7.6.48", "1.3.6.1.5.5.7.6.51" }) {
            Assert.ThrowsExactly<NotSupportedException>(() => SignatureScheme.CreateFromOid(new Oid(oid)));
        }
    }
    [TestMethod]
    public void SignatureOfRealCertificatesIsDecodedAndVerified() {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using RSA rsa = RSA.Create(2048);
        using var ecKey = new ECDsaPublicKey(ecdsa);
        using var rsaKey = new RsaPublicKey(rsa);

        using X509Certificate2 ecCert = createSelfSigned(new CertificateRequest("CN=ec", ecdsa, HashAlgorithmName.SHA256));
        using X509Certificate2 pkcsCert = createSelfSigned(new CertificateRequest("CN=rsa", rsa, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
        using X509Certificate2 pssCert = createSelfSigned(new CertificateRequest("CN=pss", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        SignedCase[] cases = [
            new(createBlob(ecCert), ecKey, "sha256ECDSA"),
            new(createBlob(pkcsCert), rsaKey, "sha384RSA"),
            new(createBlob(pssCert), rsaKey, "RSASSA-PSS")
        ];
        foreach (SignedCase c in cases) {
            SignatureScheme scheme = SignatureScheme.Decode(c.Blob.SignatureAlgorithm);
            Assert.AreEqual(c.SchemeName, scheme.AlgorithmId.FriendlyName);
            // the scheme is what the certificate says, and it re-encodes to the same identifier
            CollectionAssert.AreEqual(c.Blob.SignatureAlgorithm.RawData, scheme.ToAlgorithmIdentifier().RawData);
            Byte[] signature = c.Key.DecodeSignature(c.Blob.Signature.GetValue().ToArray());
            Assert.IsTrue(c.Key.VerifyData(c.Blob.ToBeSignedData, signature, scheme));
            signature[^1] ^= 1;
            Assert.IsFalse(c.Key.VerifyData(c.Blob.ToBeSignedData, signature, scheme));
        }
    }
}
