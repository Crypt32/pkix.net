#nullable enable
using System;
using System.Security.Cryptography;
using System.Text;

namespace SysadminsLV.PKI.Cryptography;

/// <summary>
/// Represents a scheme information of composite ML-DSA signature algorithms (<see href="https://www.rfc-editor.org/rfc/rfc10073.html">RFC 10073</see>),
/// for example <strong>MLDSA65-ECDSA-P256-SHA512</strong>.
/// </summary>
/// <remarks>
/// A composite algorithm is identified by a single object identifier that is used for both, the public key and the
/// signature algorithm, and the <strong>parameters</strong> field of algorithm identifier is absent. Everything else
/// (ML-DSA level, traditional algorithm and its parameters, pre-hash algorithm, domain separation label) is implied
/// by the object identifier and is described by this class.
/// </remarks>
public sealed class CompositeSignatureSchemeParams : ISignatureSchemeParams {
    // domain separator that is used in message representative: ASCII "CompositeAlgorithmSignatures2025"
    static readonly Byte[] _prefix = Encoding.ASCII.GetBytes("CompositeAlgorithmSignatures2025");

    internal CompositeSignatureSchemeParams(
        String name,
        Oid mlDsaAlgorithm,
        Oid preHashAlgorithm,
        SignatureScheme traditionalScheme,
        Int32 traditionalRsaKeySize,
        Oid? traditionalCurve) {
        Name = name;
        MLDsaAlgorithm = mlDsaAlgorithm;
        HashAlgorithm = preHashAlgorithm;
        TraditionalScheme = traditionalScheme;
        TraditionalRsaKeySize = traditionalRsaKeySize;
        TraditionalCurve = traditionalCurve;
    }

    /// <summary>
    /// Gets the name of the composite algorithm, for example <strong>MLDSA65-ECDSA-P256-SHA512</strong>.
    /// </summary>
    public String Name { get; }
    /// <summary>
    /// Gets the signature label of the composite algorithm. The label is used as ML-DSA context string and as
    /// a part of the message representative.
    /// </summary>
    public String Label => "COMPSIG-" + Name;
    /// <summary>
    /// Gets the object identifier of the ML-DSA component (defines the ML-DSA level).
    /// </summary>
    public Oid MLDsaAlgorithm { get; }
    /// <summary>
    /// Gets the pre-hash algorithm that is used to hash the message before it is signed by both components.
    /// </summary>
    public Oid HashAlgorithm { get; }
    /// <summary>
    /// Gets the signature scheme of the traditional component. Note that the scheme doesn't imply that the traditional
    /// algorithm is implemented on a current platform (for example, brainpool curves).
    /// </summary>
    public SignatureScheme TraditionalScheme { get; }
    /// <summary>
    /// Gets the RSA modulus size, in bits, required by the algorithm. The value is zero if the traditional component is not RSA.
    /// </summary>
    public Int32 TraditionalRsaKeySize { get; }
    /// <summary>
    /// Gets the elliptic curve required by the algorithm. The value is <strong>null</strong> if the traditional component
    /// is not ECDSA.
    /// </summary>
    public Oid? TraditionalCurve { get; }

    /// <summary>
    /// Gets the domain separator prefix of the message representative.
    /// </summary>
    public static Byte[] GetPrefix() {
        return (Byte[])_prefix.Clone();
    }
    /// <summary>
    /// Creates a message representative <strong>M'</strong> that is signed by both components:
    /// <c>Prefix || Label || len(ctx) || ctx || PH(M)</c>.
    /// </summary>
    /// <param name="message">Message to sign.</param>
    /// <param name="context">Optional context string, up to 255 bytes.</param>
    /// <exception cref="ArgumentNullException"><strong>message</strong> is null.</exception>
    /// <exception cref="ArgumentException"><strong>context</strong> is longer than 255 bytes.</exception>
    /// <returns>Message representative.</returns>
    /// <remarks>
    /// This is a prototype. The construction follows <see href="https://www.rfc-editor.org/rfc/rfc10073.html#name-algorithm-identifiers-and-p">RFC 10073 §6</see>
    /// and is not yet verified against the draft test vectors.
    /// </remarks>
    public Byte[] CreateMessageRepresentative(Byte[] message, Byte[]? context = null) {
        if (message is null) {
            throw new ArgumentNullException(nameof(message));
        }
        context ??= [];
        if (context.Length > Byte.MaxValue) {
            throw new ArgumentException("Context must not be longer than 255 bytes.", nameof(context));
        }

        Byte[] preHash = HashUtils.ComputeHash(HashAlgorithm, message);
        Byte[] label = Encoding.ASCII.GetBytes(Label);
        Byte[] result = new Byte[_prefix.Length + label.Length + 1 + context.Length + preHash.Length];
        Int32 offset = 0;
        append(_prefix);
        append(label);
        result[offset++] = (Byte)context.Length;
        append(context);
        append(preHash);

        return result;

        void append(Byte[] source) {
            Buffer.BlockCopy(source, 0, result, offset, source.Length);
            offset += source.Length;
        }
    }

    /// <inheritdoc />
    /// <remarks>Composite algorithms don't have parameters in algorithm identifier.</remarks>
    public Byte[]? Encode() {
        return null;
    }
}
