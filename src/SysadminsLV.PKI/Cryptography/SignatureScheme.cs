#nullable enable
using System;
using System.Security.Cryptography;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a signature scheme: a signature algorithm identifier (mandatory) and an optional additional information
/// about the scheme (<see cref="Parameters"/>), such as the hash algorithm, PSS salt, or nested schemes of composite algorithms.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AlgorithmId"/> is exactly the object identifier that is stored in the signature algorithm field of
/// signed structures: <strong>sha256RSA</strong>, <strong>RSASSA-PSS</strong>, <strong>specifiedECDSA</strong>,
/// <strong>ML-DSA-65</strong>, <strong>MLDSA65-ECDSA-P256-SHA512</strong> and so on.
/// </para>
/// <para>
/// <see cref="Parameters"/> are broader than ASN.1 parameters of <see cref="AlgorithmIdentifier"/>. Only
/// <see cref="ToAlgorithmIdentifier"/> defines the binary representation, and <see cref="Decode(AlgorithmIdentifier)"/>
/// is its inverse.
/// </para>
/// <para>
/// A scheme describes the signature format only. Whether the scheme is implemented on a current platform is the
/// responsibility of a key pair.
/// </para>
/// </remarks>
public sealed class SignatureScheme : IEquatable<SignatureScheme> {
    const String ERR_PARAMS_ABSENT = "The parameters field of the algorithm identifier must be absent.";
    readonly Oid _algorithmId;
    readonly Oid? _keyAlgorithm;

    SignatureScheme(Oid algorithmId, Oid? keyAlgorithm, ISignatureSchemeParams? parameters, Boolean isNoSign) {
        _algorithmId = algorithmId;
        _keyAlgorithm = keyAlgorithm;
        Parameters = parameters;
        IsNoSign = isNoSign;
    }

    /// <summary>
    /// Gets the signature algorithm identifier that is stored in the signature algorithm field of signed structures.
    /// The friendly name is resolved from the system OID database (signature algorithm group), for example
    /// <strong>sha256RSA</strong> or <strong>sha1NoSign</strong>, and is empty when the platform doesn't know the algorithm.
    /// </summary>
    public Oid AlgorithmId => copy(_algorithmId);
    /// <summary>
    /// Gets the object identifier of the key algorithm that is required by the scheme. The value is <strong>null</strong>
    /// for <strong>NoSign</strong> schemes, because they don't use a key. For ML-DSA, SLH-DSA and composite algorithms
    /// the key algorithm identifier is the same as <see cref="AlgorithmId"/>.
    /// </summary>
    public Oid? KeyAlgorithm => _keyAlgorithm is null ? null : copy(_keyAlgorithm);
    /// <summary>
    /// Gets additional information about the scheme. The value is <strong>null</strong> for schemes that don't
    /// have it (pure ML-DSA, SLH-DSA and EdDSA).
    /// </summary>
    public ISignatureSchemeParams? Parameters { get; }
    /// <summary>
    /// Gets the hash algorithm of the scheme, or <strong>null</strong> if the scheme is not hash-based (pure ML-DSA and SLH-DSA).
    /// For composite schemes this is the pre-hash algorithm.
    /// </summary>
    public Oid? HashAlgorithm => Parameters is null ? null : new Oid(Parameters.HashAlgorithm.Value);
    /// <summary>
    /// Gets the value that indicates whether the scheme is a "null-signed" identifier (<strong>sha1NoSign</strong>,
    /// <strong>sha256NoSign</strong> and so on). In this case the signature is a plain hash of data and there is no key.
    /// </summary>
    public Boolean IsNoSign { get; }
    /// <summary>
    /// Gets the value that indicates whether the scheme is a composite algorithm.
    /// </summary>
    public Boolean IsComposite => Parameters is CompositeSignatureSchemeParams;

    /// <summary>
    /// Encodes the scheme to the algorithm identifier that is stored in signed structures.
    /// </summary>
    /// <returns>Algorithm identifier.</returns>
    public AlgorithmIdentifier ToAlgorithmIdentifier() {
        // null: parameters field is absent.
        return new AlgorithmIdentifier(AlgorithmId, Parameters?.Encode());
    }

    /// <summary>
    /// Decodes the scheme from the signature algorithm identifier.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded algorithm identifier.</param>
    /// <exception cref="ArgumentNullException"><strong>rawData</strong> is null.</exception>
    /// <exception cref="NotSupportedException">The signature algorithm is not known.</exception>
    /// <exception cref="ArgumentException">Algorithm identifier parameters are not valid for the algorithm.</exception>
    /// <returns>Signature scheme.</returns>
    public static SignatureScheme Decode(Byte[] rawData) {
        if (rawData is null) {
            throw new ArgumentNullException(nameof(rawData));
        }

        return Decode(new AlgorithmIdentifier(rawData));
    }
    /// <summary>
    /// Decodes the scheme from the signature algorithm identifier. The identifier is interpreted as a
    /// signature algorithm: a hash algorithm identifier is interpreted as <strong>NoSign</strong> scheme.
    /// </summary>
    /// <param name="algorithmIdentifier">Signature algorithm identifier.</param>
    /// <exception cref="ArgumentNullException"><strong>algorithmIdentifier</strong> is null.</exception>
    /// <exception cref="NotSupportedException">The signature algorithm is not known.</exception>
    /// <exception cref="ArgumentException">Algorithm identifier parameters are not valid for the algorithm.</exception>
    /// <returns>Signature scheme.</returns>
    public static SignatureScheme Decode(AlgorithmIdentifier algorithmIdentifier) {
        if (algorithmIdentifier is null) {
            throw new ArgumentNullException(nameof(algorithmIdentifier));
        }

        String oid = algorithmIdentifier.AlgorithmId.Value!;
        Byte[]? wire = algorithmIdentifier.Parameters;
        switch (oid) {
            case AlgorithmOid.RSA_PSS:
                return CreatePss(RsaPssParameters.Decode(wire ?? throw new ArgumentException("RSASSA-PSS requires parameters.")));
            case AlgorithmOid.ECDSA_SPECIFIED:
                return CreateSpecifiedEcdsa(SpecifiedEcdsaParameters.Decode(wire ?? throw new ArgumentException("specifiedECDSA requires parameters.")).HashAlgorithm);
        }
        if (SignatureSchemeRegistry.FindClassic(oid) is { } classic) {
            // RSA: NULL, ECDSA and DSA: absent. Some producers add NULL to ECDSA and DSA identifiers too, so be tolerant.
            if (wire is not null && !isNull(wire)) {
                throw new ArgumentException("Unexpected parameters in the algorithm identifier.");
            }

            return CreateClassic(new Oid(classic.KeyAlgorithm), new Oid(classic.Hash));
        }
        if (SignatureSchemeRegistry.IsNoSign(oid)) {
            if (wire is not null && !isNull(wire)) {
                throw new ArgumentException("Unexpected parameters in the algorithm identifier.");
            }

            return CreateNoSign(new Oid(oid));
        }
        if (SignatureSchemeRegistry.IsPure(oid) || SignatureSchemeRegistry.FindComposite(oid) is not null) {
            if (wire is not null) {
                throw new ArgumentException(ERR_PARAMS_ABSENT);
            }

            return CreateFromOid(new Oid(oid));
        }

        throw new NotSupportedException($"Signature algorithm '{oid}' is not supported.");
    }

    /// <summary>
    /// Creates a classic composite scheme, such as <strong>sha256RSA</strong> or <strong>sha384ECDSA</strong>.
    /// </summary>
    /// <param name="keyAlgorithm">Key algorithm: RSA, ECC or DSA.</param>
    /// <param name="hashAlgorithm">Hash algorithm.</param>
    /// <exception cref="ArgumentNullException">A parameter is null.</exception>
    /// <exception cref="NotSupportedException">There is no signature algorithm for the key and hash combination.</exception>
    /// <returns>Signature scheme.</returns>
    public static SignatureScheme CreateClassic(Oid keyAlgorithm, Oid hashAlgorithm) {
        if (keyAlgorithm is null) {
            throw new ArgumentNullException(nameof(keyAlgorithm));
        }
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        SignatureSchemeRegistry.ClassicEntry entry = SignatureSchemeRegistry.FindClassic(keyAlgorithm.Value!, hashAlgorithm.Value!)
            ?? throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Value}' is not supported with key algorithm '{keyAlgorithm.Value}'.");

        return new SignatureScheme(
            resolveSignature(entry.Oid),
            resolveKey(entry.KeyAlgorithm),
            new ClassicSignatureSchemeParams(hashAlgorithm, entry.KeyAlgorithm == AlgorithmOid.RSA),
            false);
    }
    /// <summary>
    /// Creates an RSASSA-PSS scheme with salt length that is equal to the hash length.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm.</param>
    /// <exception cref="ArgumentNullException"><strong>hashAlgorithm</strong> is null.</exception>
    /// <exception cref="ArgumentException">The hash algorithm is not supported.</exception>
    /// <returns>Signature scheme.</returns>
    public static SignatureScheme CreatePss(Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        return CreatePss(RsaPssParameters.CreateDefault(hashAlgorithm));
    }
    /// <summary>
    /// Creates an RSASSA-PSS scheme from PSS parameters.
    /// </summary>
    /// <param name="parameters">PSS parameters.</param>
    /// <exception cref="ArgumentNullException"><strong>parameters</strong> is null.</exception>
    /// <returns>Signature scheme.</returns>
    internal static SignatureScheme CreatePss(RsaPssParameters parameters) {
        if (parameters is null) {
            throw new ArgumentNullException(nameof(parameters));
        }

        return new SignatureScheme(resolveSignature(AlgorithmOid.RSA_PSS), resolveKey(AlgorithmOid.RSA), parameters, false);
    }
    /// <summary>
    /// Creates a specified ECDSA scheme.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm.</param>
    /// <exception cref="ArgumentNullException"><strong>hashAlgorithm</strong> is null.</exception>
    /// <returns>Signature scheme.</returns>
    public static SignatureScheme CreateSpecifiedEcdsa(Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        return new SignatureScheme(
            resolveSignature(AlgorithmOid.ECDSA_SPECIFIED),
            resolveKey(AlgorithmOid.ECC),
            new SpecifiedEcdsaParameters(hashAlgorithm),
            false);
    }
    /// <summary>
    /// Creates a "null-signed" scheme (<strong>sha1NoSign</strong>, <strong>sha256NoSign</strong> and so on), where
    /// the signature is a plain hash of data. This kind of identifier is used, for example, in inner PKCS#10 requests
    /// of CMC messages.
    /// </summary>
    /// <param name="hashAlgorithm">Hash algorithm.</param>
    /// <exception cref="ArgumentNullException"><strong>hashAlgorithm</strong> is null.</exception>
    /// <exception cref="NotSupportedException">There is no NoSign identifier for the hash algorithm.</exception>
    /// <returns>Signature scheme.</returns>
    public static SignatureScheme CreateNoSign(Oid hashAlgorithm) {
        if (hashAlgorithm is null) {
            throw new ArgumentNullException(nameof(hashAlgorithm));
        }

        if (!SignatureSchemeRegistry.IsNoSign(hashAlgorithm.Value!)) {
            throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Value}' doesn't have NoSign identifier.");
        }

        // the identifier is the hash OID, the same way as it is written by SignedContentBlob.Hash.
        return new SignatureScheme(resolveSignature(hashAlgorithm.Value!), null, new ClassicSignatureSchemeParams(hashAlgorithm, true), true);
    }
    /// <summary>
    /// Creates a scheme for algorithms that are fully defined by the object identifier: ML-DSA, SLH-DSA, EdDSA
    /// and composite ML-DSA.
    /// </summary>
    /// <param name="algorithmId">Signature (and key) algorithm identifier.</param>
    /// <exception cref="ArgumentNullException"><strong>algorithmId</strong> is null.</exception>
    /// <exception cref="NotSupportedException">The algorithm is not known.</exception>
    /// <returns>Signature scheme.</returns>
    public static SignatureScheme CreateFromOid(Oid algorithmId) {
        if (algorithmId is null) {
            throw new ArgumentNullException(nameof(algorithmId));
        }

        String oid = algorithmId.Value!;
        if (SignatureSchemeRegistry.IsPure(oid)) {
            return new SignatureScheme(resolveSignature(oid), resolveKey(oid), null, false);
        }
        if (SignatureSchemeRegistry.FindComposite(oid) is { } parameters) {
            return new SignatureScheme(resolveSignature(oid), resolveKey(oid), parameters, false);
        }

        throw new NotSupportedException($"Signature algorithm '{oid}' is not supported.");
    }

    // names come from the system OID database, group-specific: the same value can have different names in the hash and
    // signature algorithm groups (sha1 vs sha1NoSign), and this is what system viewers display.
    static Oid resolveSignature(String oid) {
        return resolve(oid, OidGroup.SignatureAlgorithm);
    }
    static Oid resolveKey(String oid) {
        return resolve(oid, OidGroup.PublicKeyAlgorithm);
    }
    static Oid resolve(String oid, OidGroup group) {
        try {
            return Oid.FromOidValue(oid, group);
        } catch (CryptographicException) {
            // not registered in the group: no friendly name. An empty name stops Oid from searching other groups, where
            // the same value can have an unrelated name.
            return new Oid(oid, String.Empty);
        }
    }
    static Oid copy(Oid oid) {
        return new Oid(oid.Value, oid.FriendlyName);
    }
    static Boolean isNull(Byte[] parameters) {
        return parameters.Length == 2 && parameters[0] == 5 && parameters[1] == 0;
    }

    /// <inheritdoc />
    public Boolean Equals(SignatureScheme? other) {
        if (other is null) {
            return false;
        }
        if (ReferenceEquals(this, other)) {
            return true;
        }

        return _algorithmId.Value == other._algorithmId.Value
               && IsNoSign == other.IsNoSign
               && (Parameters?.Encode() ?? []).SequenceEqual(other.Parameters?.Encode() ?? [])
               && Parameters?.HashAlgorithm.Value == other.Parameters?.HashAlgorithm.Value;
    }
    /// <inheritdoc />
    public override Boolean Equals(Object? obj) {
        return Equals(obj as SignatureScheme);
    }
    /// <inheritdoc />
    public override Int32 GetHashCode() {
        unchecked {
            Int32 hash = _algorithmId.Value!.GetHashCode();
            hash = hash * 397 ^ IsNoSign.GetHashCode();
            return hash * 397 ^ (Parameters?.HashAlgorithm.Value?.GetHashCode() ?? 0);
        }
    }
    /// <inheritdoc />
    public override String ToString() {
        return _algorithmId.Format(false);
    }
}
