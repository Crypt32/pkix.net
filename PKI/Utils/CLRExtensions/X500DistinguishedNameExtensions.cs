﻿using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SysadminsLV.Asn1Parser;

namespace PKI.Utils.CLRExtensions {
	/// <summary>
	/// Contains extension methods for <see cref="X500DistinguishedName"/> class.
	/// </summary>
	public static class X500DistinguishedNameExtensions {
		/// <summary>
		/// 
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public static X500RdnAttributeCollection GetRdnAttributes(this X500DistinguishedName name) {
			if (name == null) { throw new ArgumentNullException(nameof(name)); }
			if (name.RawData == null || name.RawData.Length == 0) { return null; }
			Asn1Reader asn = new Asn1Reader(name.RawData);
			if (!asn.MoveNext()) { return null; }
			if (asn.NextCurrentLevelOffset == 0) { return null; }
			var retValue = new X500RdnAttributeCollection();
			do {
				Asn1Reader asn2 = new Asn1Reader(asn.GetPayload());
				asn2.MoveNext();
				Oid oid = Asn1Utils.DecodeObjectIdentifier(asn2.GetTagRawData());
				asn2.MoveNext();
				String value = Asn1Utils.DecodeAnyString(asn2.GetTagRawData(), null);
				retValue.Add(new X500RdnAttribute(oid, value));

			} while (asn.MoveNextCurrentLevel());
			return retValue;
		}
	}
}
