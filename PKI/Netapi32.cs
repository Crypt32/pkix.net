﻿using System;
using System.Runtime.InteropServices;

namespace PKI {
	static class Netapi32 {
		[DllImport("Netapi32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern Int32 DsGetSiteName(
			[In]			String ComputerName,
			[In, Out]ref	String SiteName
		);
	}
}
