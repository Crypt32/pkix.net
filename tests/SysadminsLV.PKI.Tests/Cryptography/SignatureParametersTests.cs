using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.PKI.Cryptography;

namespace SysadminsLV.PKI.Tests.Cryptography;

[TestClass]
public class SignatureParametersTests {
    [TestMethod]
    [DataRow(AlgorithmOid.SHA1, 20)]
    [DataRow(AlgorithmOid.SHA256, 32)]
    [DataRow(AlgorithmOid.SHA384, 48)]
    [DataRow(AlgorithmOid.SHA512, 64)]
    public void PssDefaultSaltEqualsHashLength(String hashOid, Int32 expectedSalt) {
        var p = RsaPssParameters.CreateDefault(new Oid(hashOid));
        Assert.AreEqual(expectedSalt, p.SaltLength);
        Assert.AreEqual(hashOid, p.HashAlgorithm.Value);
        Assert.AreEqual(hashOid, p.MaskGenHashAlgorithm.Value);
    }
    [TestMethod]
    [DataRow(AlgorithmOid.SHA1, 20)]
    [DataRow(AlgorithmOid.SHA256, 32)]
    [DataRow(AlgorithmOid.SHA256, 20)]
    [DataRow(AlgorithmOid.SHA384, 0)]
    [DataRow(AlgorithmOid.SHA512, 64)]
    [DataRow(AlgorithmOid.SHA512, 130)]
    public void PssRoundTripPreservesSalt(String hashOid, Int32 salt) {
        var original = new RsaPssParameters(new Oid(hashOid), salt);
        var decoded = RsaPssParameters.Decode(original.Encode());
        Assert.AreEqual(salt, decoded.SaltLength);
        Assert.AreEqual(hashOid, decoded.HashAlgorithm.Value);
        Assert.AreEqual(hashOid, decoded.MaskGenHashAlgorithm.Value);
        CollectionAssert.AreEqual(original.Encode(), decoded.Encode());
    }
    [TestMethod]
    public void PssAlgorithmIdentifierCarriesRealSalt() {
        var alg = SignatureScheme.CreatePss(new RsaPssParameters(new Oid(AlgorithmOid.SHA256), 32)).ToAlgorithmIdentifier();
        Assert.AreEqual(AlgorithmOid.RSA_PSS, alg.AlgorithmId.Value);
        Assert.AreEqual(32, RsaPssParameters.Decode(alg.Parameters).SaltLength);
    }
    [TestMethod]
    public void PssDecodeEmptySequenceYieldsDefaults() {
        var p = RsaPssParameters.Decode([0x30, 0x00]);
        Assert.AreEqual(AlgorithmOid.SHA1, p.HashAlgorithm.Value);
        Assert.AreEqual(AlgorithmOid.SHA1, p.MaskGenHashAlgorithm.Value);
        Assert.AreEqual(20, p.SaltLength);
    }
    [TestMethod]
    public void PssDecodeSaltOnlyKeepsDefaultHash() {
        // SEQUENCE { [2] { INTEGER 32 } }
        var p = RsaPssParameters.Decode([0x30, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x20]);
        Assert.AreEqual(AlgorithmOid.SHA1, p.HashAlgorithm.Value);
        Assert.AreEqual(32, p.SaltLength);
    }
    [TestMethod]
    public void PssRejectsUnsupportedHash() {
        Assert.ThrowsExactly<ArgumentException>(() => RsaPssParameters.CreateDefault(new Oid("1.2.3.4")));
    }
    [TestMethod]
    public void PssRejectsNegativeSalt() {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new RsaPssParameters(new Oid(AlgorithmOid.SHA256), -1));
    }
    [TestMethod]
    public void PssRejectsNonMgf1() {
        // SEQUENCE { [1] { SEQUENCE { OID 1.2.3 } } }
        Byte[] raw = [0x30, 0x07, 0xa1, 0x05, 0x30, 0x03, 0x06, 0x01, 0x2a];
        Assert.ThrowsExactly<NotSupportedException>(() => RsaPssParameters.Decode(raw));
    }
    [TestMethod]
    [DataRow(AlgorithmOid.SHA256)]
    [DataRow(AlgorithmOid.SHA384)]
    [DataRow(AlgorithmOid.SHA512)]
    public void SpecifiedEcdsaRoundTrip(String hashOid) {
        var original = new SpecifiedEcdsaParameters(new Oid(hashOid));
        var decoded = SpecifiedEcdsaParameters.Decode(original.Encode());
        Assert.AreEqual(hashOid, decoded.HashAlgorithm.Value);
        var alg = SignatureScheme.CreateSpecifiedEcdsa(new Oid(hashOid)).ToAlgorithmIdentifier();
        Assert.AreEqual(AlgorithmOid.ECDSA_SPECIFIED, alg.AlgorithmId.Value);
        CollectionAssert.AreEqual(original.Encode(), alg.Parameters);
    }
}
