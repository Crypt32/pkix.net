Packages in this repo:
- [SysadminsLV.PKI](#sysadminslvpki-package)
- [SysadminsLV.PKI.OcspClient](#sysadminslvpkiocspclient-package)
- [SysadminsLV.PKI.Win](#sysadminslvpkiwin-package)
---

# API Documentation
- [Unified documentation](https://www.pkisolutions.com/apidocs/pki)

# SysadminsLV.PKI package

## Description
This package is a cross-platform framework library that provides extended cryptography and X.509 support classes to standard .NET frameworks.

## Requirements
- .NET Standard 2.0/.NET 4.7.2
- Cross-platform

## Dependencies
This project requires the following NuGet packages:
- [SysadminsLV.Asn1Parser](https://www.nuget.org/packages/SysadminsLV.Asn1Parser)

## CI/CD and NuGet Status

![Build status](https://dev.azure.com/SysadminsLV-DEV/NuGet%20Libraries/_apis/build/status/PSPKI/SysadminsLV.PKI-Nupkg)
![image](https://vsrm.dev.azure.com/SysadminsLV-DEV/_apis/public/Release/badge/78e820b9-7991-4b20-aaae-2f6ba4c23e90/6/6)
![image](https://img.shields.io/nuget/v/SysadminsLV.PKI)

# SysadminsLV.PKI.OcspClient package

## Description
This package is a cross-platform framework library that implements managed OCSP client which is compatible with [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) OCSP profile.

## Requirements
- .NET Standard 2.0/.NET 4.7.2
- Cross-platform

## Dependencies
This project requires the following NuGet packages:
- [SysadminsLV.Asn1Parser](https://www.nuget.org/packages/SysadminsLV.Asn1Parser)
- [SysadminsLV.PKI](https://www.nuget.org/packages/SysadminsLV.PKI)

## CI/CD and NuGet Status
![Build Status](https://dev.azure.com/SysadminsLV-DEV/NuGet%20Libraries/_apis/build/status/SysadminsLV.PKI.OcspClient-Nupkg)
![image](https://vsrm.dev.azure.com/SysadminsLV-DEV/_apis/public/Release/badge/78e820b9-7991-4b20-aaae-2f6ba4c23e90/5/5)
![image](https://img.shields.io/nuget/v/SysadminsLV.PKI.OcspClient)


# SysadminsLV.PKI.Win package

## Description
This package is a Windows-specific framework library that that provides extended cryptography and implements managed Active Directory Certificate Services (ADCS) classes.

## Requirements
- .NET 4.7.2
- Windows-platform

## Dependencies
This project requires the following NuGet packages:
- [SysadminsLV.Asn1Parser](https://www.nuget.org/packages/SysadminsLV.Asn1Parser)
- [SysadminsLV.PKI](https://www.nuget.org/packages/SysadminsLV.PKI)
- [SysadminsLV.PKI.OcspClient](https://www.nuget.org/packages/SysadminsLV.PKI.OcspClient)

## CI/CD and NuGet Status
![Build Status](https://dev.azure.com/SysadminsLV-DEV/NuGet%20Libraries/_apis/build/status/SysadminsLV.PKI.Win-Nupkg)
![image](https://vsrm.dev.azure.com/SysadminsLV-DEV/_apis/public/Release/badge/78e820b9-7991-4b20-aaae-2f6ba4c23e90/4/4)
![image](https://img.shields.io/nuget/v/SysadminsLV.PKI.Win)
