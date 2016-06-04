﻿using PKI.Exceptions;
using PKI.ManagedAPI;
using PKI.ManagedAPI.StructClasses;
using PKI.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace PKI.OCSP {
	/// <summary>
	///  The class represents an object to identify the certificate to include in OCSP Request. Also this object is returned by the OCSP Responder.
	/// </summary>
	public class CertID {
		Oid hashAlgorithm = new Oid("1.3.14.3.2.26"); // sha1
		readonly X500DistinguishedName _issuerName;
		Byte[] issuerPublicKey, serialNumber;

		/// <param name="rawData">A DER-encoded byte array that represents a binary form of <strong>CertID</strong> object.</param>
		/// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
		public CertID(Byte[] rawData) {
			if (rawData == null) { throw new ArgumentNullException("rawData"); }
			initializeFromAsn(rawData);
		}
		/// <param name="cert">An <see cref="X509Certificate2"/> from which the <strong>CertID</strong> object is constructed.</param>
		/// <exception cref="ArgumentNullException"><strong>cert</strong> parameter is null reference.</exception>
		/// <exception cref="UninitializedObjectException">
		///		The certificate is not initialized.
		/// </exception>
		public CertID(X509Certificate2 cert) {
			if (cert == null) { throw new ArgumentNullException("cert"); }
			if (cert.Handle.Equals(IntPtr.Zero)) { throw new UninitializedObjectException(); }
			_issuerName = cert.IssuerName;
			serialNumber = cert.GetSerialNumber().Reverse().ToArray();
			initializeFromCert(cert);
		}

		/// <summary>
		/// Initializes a new instance of the <strong>CertID</strong> class using leaf and issuer certificates.
		/// This constructor do not check whether the certificate in the <strong>issuer</strong> parameter actually
		/// signed the certificate in the <strong>leafCert</strong> parameter.
		/// </summary>
		/// <param name="issuer">
		///		An <see cref="X509Certificate2"/> object that represents an issuer.
		/// </param>
		/// <param name="leafCert">
		///		An <see cref="X509Certificate2"/> object that represents certificate to verify.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// Either, a <strong>issuer</strong> and/or <strong>leafCert</strong> parameter is null.
		/// </exception>
		public CertID(X509Certificate2 issuer, X509Certificate2 leafCert) {
			if (issuer == null) { throw new ArgumentNullException("issuer"); }
			if (leafCert == null) { throw new ArgumentNullException("leafCert"); }
			_issuerName = issuer.SubjectName;
			issuerPublicKey = issuer.GetPublicKey();
			serialNumber = leafCert.GetSerialNumber().Reverse().ToArray();
			initializeFromCertAndIssuer();
		}

		/// <summary>
		/// Gets or sets the algorithm used to hash properties of a certificate.
		/// <remarks>
		/// Setter accessor works only when <see cref="IsReadOnly"/> member is set to <strong>False</strong>,
		/// otherwise it throws <see cref="ArgumentException"/> exception.
		/// </remarks>
		/// </summary>
		public Oid HashingAlgorithm {
			get { return hashAlgorithm; }
			set {
				if (IsReadOnly) { throw new InvalidOperationException(); }
				Oid2 oid2 = new Oid2(value.Value, OidGroupEnum.HashAlgorithm, false);
				if (String.IsNullOrEmpty(oid2.Value)) {
					throw new ArgumentException("The algorithm is invalid");
				}
				hashAlgorithm = value;
			}
		}
		/// <summary>
		///  Gets the hash of the Issuer's distinguished name.
		/// </summary>
		public String IssuerNameId { get; private set; }
		/// <summary>
		///  The hash calculated over the value (excluding tag and length) of the subject public key field in the issuer's certificate.
		/// </summary>
		public String IssuerKeyId { get; private set; }
		/// <summary>
		///  Gets the serial number of the certificate for which status is being requested.
		/// </summary>
		public String SerialNumber {
			get {
				return AsnFormatter.BinaryToString(serialNumber).Trim();
			}
		}
		/// <summary>
		/// Gets the status of the object and an ability to change <see cref="HashAlgorithm"/> member.
		/// If thie member is set to <strong>True</strong>, <see cref="HashAlgorithm"/> property is read-only.
		/// </summary>
		public Boolean IsReadOnly { get; private set; }

		void initializeFromAsn(Byte[] rawData) {
			Asn1Reader asn1 = new Asn1Reader(rawData);
			if (asn1.Tag != 48) {
				throw new Exception("Unable to decode. Input data is not valid ASN.1 encoded data.");
			}
			asn1.MoveNext();
			HashingAlgorithm = (new AlgorithmIdentifier(Asn1Utils.Encode(asn1.GetPayload(), 48))).AlgorithmId;
			asn1.MoveNextCurrentLevel();
			// issuerNameHash
			if (asn1.Tag != 4) { throw new Exception("Unable to decode. The data is invalid"); }
			IssuerNameId = AsnFormatter.BinaryToString(asn1.GetPayload()).Trim();
			asn1.MoveNextCurrentLevel();
			// issuerKeyId
			if (asn1.Tag != 4) { throw new Exception("Unable to decode. The data is invalid"); }
			IssuerKeyId = AsnFormatter.BinaryToString(asn1.GetPayload()).Trim();
			asn1.MoveNextCurrentLevel();
			// serialnumber
			if (asn1.Tag != 2) { throw new Exception("Unable to decode. The data is invalid"); }
			serialNumber = asn1.GetPayload();
			IsReadOnly = true;
		}
		void initializeFromCert(X509Certificate2 cert) {
			X509Chain chain = new X509Chain { ChainPolicy = { RevocationMode = X509RevocationMode.NoCheck } };
			chain.Build(cert);
			if (chain.ChainElements.Count <= 1) {
				throw new Exception("Issuer for the speified certificate not found.");
			}
			X509Certificate2 issuer = chain.ChainElements[1].Certificate;
			issuerPublicKey = issuer.GetPublicKey();
			using (HashAlgorithm hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName)) {
				IssuerNameId = AsnFormatter.BinaryToString(hasher.ComputeHash(cert.IssuerName.RawData)).Trim();
			}
			using (HashAlgorithm hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName)) {
				IssuerKeyId = AsnFormatter.BinaryToString(hasher.ComputeHash(issuer.GetPublicKey())).Trim();
			}
		}
		void initializeFromCertAndIssuer() {
			using (HashAlgorithm hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName)) {
				IssuerNameId = AsnFormatter.BinaryToString(hasher.ComputeHash(_issuerName.RawData)).Trim();
			}
			using (HashAlgorithm hasher = HashAlgorithm.Create(hashAlgorithm.FriendlyName)) {
				IssuerKeyId = AsnFormatter.BinaryToString(hasher.ComputeHash(issuerPublicKey)).Trim();
			}
		}

		/// <summary>
		/// Encodes current object to a DER-encoded byte array. Returned array is used to construct initial OCSP Request structure.
		/// </summary>
		/// <returns>Returns a DER-encoded byte array.</returns>
		/// <value>System.Byte[]</value>
		public Byte[] Encode() {
			if (!String.IsNullOrEmpty(SerialNumber)) {
				if (issuerPublicKey != null) {
					initializeFromCertAndIssuer();
				}
				// algorithm identifier
				var rawData = new List<Byte>(Asn1Utils.EncodeObjectIdentifier(hashAlgorithm));
				rawData.AddRange(Asn1Utils.EncodeNull());
				rawData = new List<Byte>(Asn1Utils.Encode(rawData.ToArray(), 48));
				// IssuerNameId
				rawData.AddRange(Asn1Utils.Encode(AsnFormatter.StringToBinary(IssuerNameId, EncodingType.HexRaw), 4));
				// IssuerKeyId
				rawData.AddRange(Asn1Utils.Encode(AsnFormatter.StringToBinary(IssuerKeyId, EncodingType.HexRaw), 4));
				// SerialNumber
				rawData.AddRange(Asn1Utils.Encode(AsnFormatter.StringToBinary(SerialNumber, EncodingType.HexRaw), 2));
				IsReadOnly = true;
				return Asn1Utils.Encode(rawData.ToArray(), 48);
			}
			throw new UninitializedObjectException();
		}

		/// <summary>
		///  Compares two CertID objects for equality.
		/// </summary>
		/// <param name="obj">An CertID object to compare to the current object. </param>
		/// <remarks>Two objects are considered equal if they are CertID objects and they have the same fields:
		/// HashAlgorithm, IssuerNameId, IssuerKeyId and SerialNumber.</remarks>
		/// <returns>true if the current CertID object is equal to the object specified by the other parameter; otherwise, false.</returns>
		public Boolean Equals(CertID obj) {
			return HashingAlgorithm.Value == obj.HashingAlgorithm.Value &&
			       IssuerNameId == obj.IssuerNameId &&
			       IssuerKeyId == obj.IssuerKeyId &&
			       SerialNumber == obj.SerialNumber;
		}
	}
}
