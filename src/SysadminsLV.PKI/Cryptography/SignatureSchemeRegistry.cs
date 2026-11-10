#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Contains known signature algorithm object identifiers. The table is keyed by the object identifier value only: the
/// same value can belong to a hash algorithm and to a signature algorithm (<strong>NoSign</strong> identifiers),
/// the context (signature algorithm position of algorithm identifier) defines which one is meant.
/// </summary>
static class SignatureSchemeRegistry {
    const String COMPOSITE_ARC    = "1.3.6.1.5.5.7.6.";

    public sealed record ClassicEntry(String Oid, String KeyAlgorithm, String Hash);

    // classic composite algorithms: hash + key algorithm
    static readonly ClassicEntry[] _classic = [
        new(AlgorithmOid.MD5_RSA, AlgorithmOid.RSA, AlgorithmOid.MD5),
        new(AlgorithmOid.SHA1_RSA, AlgorithmOid.RSA, AlgorithmOid.SHA1),
        new(AlgorithmOid.SHA256_RSA, AlgorithmOid.RSA, AlgorithmOid.SHA256),
        new(AlgorithmOid.SHA384_RSA, AlgorithmOid.RSA, AlgorithmOid.SHA384),
        new(AlgorithmOid.SHA512_RSA, AlgorithmOid.RSA, AlgorithmOid.SHA512),
        new(AlgorithmOid.SHA1_ECDSA, AlgorithmOid.ECC, AlgorithmOid.SHA1),
        new(AlgorithmOid.SHA256_ECDSA, AlgorithmOid.ECC, AlgorithmOid.SHA256),
        new(AlgorithmOid.SHA384_ECDSA, AlgorithmOid.ECC, AlgorithmOid.SHA384),
        new(AlgorithmOid.SHA512_ECDSA, AlgorithmOid.ECC, AlgorithmOid.SHA512),
        new(AlgorithmOid.SHA1_DSA, AlgorithmOid.DSA, AlgorithmOid.SHA1)
    ];
    // "null-signed" identifiers: the hash OID in the signature algorithm position, signature is a plain hash
    static readonly String[] _noSign = [
        AlgorithmOid.MD5,
        AlgorithmOid.SHA1,
        AlgorithmOid.SHA256,
        AlgorithmOid.SHA384,
        AlgorithmOid.SHA512
    ];
    // algorithms without parameters, where the same OID identifies key and signature algorithm
    static readonly String[] _pure = [
        AlgorithmOid.ML_DSA_44,
        AlgorithmOid.ML_DSA_65,
        AlgorithmOid.ML_DSA_87,
        AlgorithmOid.SLH_DSA_SHA2_128S,
        AlgorithmOid.SLH_DSA_SHA2_128F,
        AlgorithmOid.SLH_DSA_SHA2_192S,
        AlgorithmOid.SLH_DSA_SHA2_192F,
        AlgorithmOid.SLH_DSA_SHA2_256S,
        AlgorithmOid.SLH_DSA_SHA2_256F,
        AlgorithmOid.SLH_DSA_SHAKE_128S,
        AlgorithmOid.SLH_DSA_SHAKE_128F,
        AlgorithmOid.SLH_DSA_SHAKE_192S,
        AlgorithmOid.SLH_DSA_SHAKE_192F,
        AlgorithmOid.SLH_DSA_SHAKE_256S,
        AlgorithmOid.SLH_DSA_SHAKE_256F
    ];
    // built lazily, because it creates signature schemes that use the tables above.
    static readonly Lazy<Dictionary<String, CompositeSignatureSchemeParams>> _composite = new(createComposite);

    public static ClassicEntry? FindClassic(String oid) {
        return _classic.FirstOrDefault(x => x.Oid == oid);
    }
    public static ClassicEntry? FindClassic(String keyAlgorithm, String hash) {
        return _classic.FirstOrDefault(x => x.KeyAlgorithm == keyAlgorithm && x.Hash == hash);
    }
    public static Boolean IsNoSign(String hash) {
        return _noSign.Contains(hash);
    }
    public static Boolean IsPure(String oid) {
        return _pure.Contains(oid);
    }
    public static CompositeSignatureSchemeParams? FindComposite(String oid) {
        return _composite.Value.TryGetValue(oid, out CompositeSignatureSchemeParams? parameters) ? parameters : null;
    }
    public static IEnumerable<String> GetCompositeOids() {
        return _composite.Value.Keys;
    }
    public static IEnumerable<String> GetPureOids() {
        return _pure;
    }

    static Dictionary<String, CompositeSignatureSchemeParams> createComposite() {
        var map = new Dictionary<String, CompositeSignatureSchemeParams>();
        // traditional components, see Appendix C of the draft. Ed25519 and Ed448 variants (OIDs 39, 48, 51) are skipped: not supported by Windows CNG.
        add(37, "MLDSA44-RSA2048-PSS-SHA256", AlgorithmOid.ML_DSA_44, AlgorithmOid.SHA256, pss(AlgorithmOid.SHA256), 2048);
        add(38, "MLDSA44-RSA2048-PKCS15-SHA256", AlgorithmOid.ML_DSA_44, AlgorithmOid.SHA256, pkcs15(AlgorithmOid.SHA256), 2048);
        add(40, "MLDSA44-ECDSA-P256-SHA256", AlgorithmOid.ML_DSA_44, AlgorithmOid.SHA256, ecdsa(AlgorithmOid.SHA256), curve: AlgorithmOid.ECDSA_P256);
        add(41, "MLDSA65-RSA3072-PSS-SHA512", AlgorithmOid.ML_DSA_65, AlgorithmOid.SHA512, pss(AlgorithmOid.SHA256), 3072);
        add(42, "MLDSA65-RSA3072-PKCS15-SHA512", AlgorithmOid.ML_DSA_65, AlgorithmOid.SHA512, pkcs15(AlgorithmOid.SHA256), 3072);
        add(43, "MLDSA65-RSA4096-PSS-SHA512", AlgorithmOid.ML_DSA_65, AlgorithmOid.SHA512, pss(AlgorithmOid.SHA384), 4096);
        add(44, "MLDSA65-RSA4096-PKCS15-SHA512", AlgorithmOid.ML_DSA_65, AlgorithmOid.SHA512, pkcs15(AlgorithmOid.SHA384), 4096);
        add(45, "MLDSA65-ECDSA-P256-SHA512", AlgorithmOid.ML_DSA_65, AlgorithmOid.SHA512, ecdsa(AlgorithmOid.SHA256), curve: AlgorithmOid.ECDSA_P256);
        add(46, "MLDSA65-ECDSA-P384-SHA512", AlgorithmOid.ML_DSA_65, AlgorithmOid.SHA512, ecdsa(AlgorithmOid.SHA384), curve: AlgorithmOid.ECDSA_P384);
        add(47, "MLDSA65-ECDSA-BP256-SHA512", AlgorithmOid.ML_DSA_65, AlgorithmOid.SHA512, ecdsa(AlgorithmOid.SHA256), curve: AlgorithmOid.BRAINPOOL_P256R1);
        add(49, "MLDSA87-ECDSA-P384-SHA512", AlgorithmOid.ML_DSA_87, AlgorithmOid.SHA512, ecdsa(AlgorithmOid.SHA384), curve: AlgorithmOid.ECDSA_P384);
        add(50, "MLDSA87-ECDSA-BP384-SHA512", AlgorithmOid.ML_DSA_87, AlgorithmOid.SHA512, ecdsa(AlgorithmOid.SHA384), curve: AlgorithmOid.BRAINPOOL_P384R1);
        add(52, "MLDSA87-RSA3072-PSS-SHA512", AlgorithmOid.ML_DSA_87, AlgorithmOid.SHA512, pss(AlgorithmOid.SHA256), 3072);
        add(53, "MLDSA87-RSA4096-PSS-SHA512", AlgorithmOid.ML_DSA_87, AlgorithmOid.SHA512, pss(AlgorithmOid.SHA384), 4096);
        add(54, "MLDSA87-ECDSA-P521-SHA512", AlgorithmOid.ML_DSA_87, AlgorithmOid.SHA512, ecdsa(AlgorithmOid.SHA512), curve: AlgorithmOid.ECDSA_P521);

        return map;

        void add(Int32 suffix, String name, String mlDsa, String preHash, SignatureScheme traditional, Int32 rsaKeySize = 0, String? curve = null) {
            map[COMPOSITE_ARC + suffix] = new CompositeSignatureSchemeParams(
                name,
                new Oid(mlDsa),
                new Oid(preHash),
                traditional,
                rsaKeySize,
                curve is null ? null : new Oid(curve));
        }
        static SignatureScheme pss(String hash) => SignatureScheme.CreatePss(new Oid(hash));
        static SignatureScheme pkcs15(String hash) => SignatureScheme.CreateClassic(new Oid(AlgorithmOid.RSA), new Oid(hash));
        static SignatureScheme ecdsa(String hash) => SignatureScheme.CreateClassic(new Oid(AlgorithmOid.ECC), new Oid(hash));
    }
}
