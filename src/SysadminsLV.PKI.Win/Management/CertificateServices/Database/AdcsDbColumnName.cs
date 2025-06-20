﻿using System;
// ReSharper disable InconsistentNaming

namespace SysadminsLV.PKI.Management.CertificateServices.Database;
static class AdcsDbColumnName {
    public const String Request_Request_ID                   = "Request.RequestID";
    public const String Request_Raw_Request                  = "Request.RawRequest";
    public const String Request_Raw_Archived_Key             = "Request.RawArchivedKey";
    public const String Request_Key_Recovery_Hashes          = "Request.KeyRecoveryHashes";
    public const String Request_Raw_Old_Certificate          = "Request.RawOldCertificate";
    public const String Request_Request_Attributes           = "Request.RequestAttributes";
    public const String Request_Request_Type                 = "Request.RequestType";
    public const String Request_Request_Flags                = "Request.RequestFlags";
    public const String Request_Status_Code                  = "Request.StatusCode";
    public const String Request_Disposition                  = "Request.Disposition";
    public const String Request_Disposition_Message          = "Request.DispositionMessage";
    public const String Request_Submitted_When               = "Request.SubmittedWhen";
    public const String Request_Resolved_When                = "Request.ResolvedWhen";
    public const String Request_Revoked_When                 = "Request.RevokedWhen";
    public const String Request_Revocation_Date              = "Request.RevokedEffectiveWhen";
    public const String Request_Revoked_Reason               = "Request.RevokedReason";
    public const String Request_Requester_Name               = "Request.RequesterName";
    public const String Request_Caller_Name                  = "Request.CallerName";
    public const String Request_Signer_Policies              = "Request.SignerPolicies";
    public const String Request_Signer_Application_Policies  = "Request.SignerApplicationPolicies";
    public const String Request_Officer                      = "Request.Officer";
    public const String Request_Distinguished_Name           = "Request.DistinguishedName";
    public const String Request_Raw_Name                     = "Request.RawName";
    public const String Request_Country                      = "Request.Country";
    public const String Request_Organization                 = "Request.Organization";
    public const String Request_Org_Unit                     = "Request.OrgUnit";
    public const String Request_Common_Name                  = "Request.CommonName";
    public const String Request_Locality                     = "Request.Locality";
    public const String Request_State                        = "Request.State";
    public const String Request_Title                        = "Request.Title";
    public const String Request_Given_Name                   = "Request.GivenName";
    public const String Request_Initials                     = "Request.Initials";
    public const String Request_SurName                      = "Request.SurName";
    public const String Request_Domain_Component             = "Request.DomainComponent";
    public const String Request_Email                        = "Request.EMail";
    public const String Request_Street_Address               = "Request.StreetAddress";
    public const String Request_Unstructured_Name            = "Request.UnstructuredName";
    public const String Request_Unstructured_Address         = "Request.UnstructuredAddress";
    public const String Request_Device_Serial_Number         = "Request.DeviceSerialNumber";
    public const String Request_Attestation_Challenge        = "Request.AttestationChallenge";
    public const String Request_Endorsement_Key_Hash         = "Request.EndorsementKeyHash";
    public const String Request_Endorsement_Certificate_Hash = "Request.EndorsementCertificateHash";
    public const String Request_ID                           = "RequestID";
    public const String Raw_Certificate                      = "RawCertificate";
    public const String Certificate_Hash                     = "CertificateHash";
    public const String Certificate_Template                 = "CertificateTemplate";
    public const String Enrollment_Flags                     = "EnrollmentFlags";
    public const String General_Flags                        = "GeneralFlags";
    public const String PrivateKey_Flags                     = "PrivateKeyFlags";
    public const String Serial_Number                        = "SerialNumber";
    public const String Issuer_Name_Id                       = "IssuerNameId";
    public const String Not_Before                           = "NotBefore";
    public const String Not_After                            = "NotAfter";
    public const String Subject_Key_Identifier               = "SubjectKeyIdentifier";
    public const String Raw_Public_Key                       = "RawPublicKey";
    public const String Public_Key_Length                    = "PublicKeyLength";
    public const String Public_Key_Algorithm                 = "PublicKeyAlgorithm";
    public const String Raw_Public_Key_Algorithm_Parameters  = "RawPublicKeyAlgorithmParameters";
    public const String Publish_Expired_Cert_In_CRL          = "PublishExpiredCertInCRL";
    public const String UPN                                  = "UPN";
    public const String Distinguished_Name                   = "DistinguishedName";
    public const String Raw_Name                             = "RawName";
    public const String Country                              = "Country";
    public const String Organization                         = "Organization";
    public const String Org_Unit                             = "OrgUnit";
    public const String Common_Name                          = "CommonName";
    public const String Locality                             = "Locality";
    public const String State                                = "State";
    public const String Title                                = "Title";
    public const String Given_Name                           = "GivenName";
    public const String Initials                             = "Initials";
    public const String SurName                              = "SurName";
    public const String Domain_Component                     = "DomainComponent";
    public const String Email                                = "EMail";
    public const String Street_Address                       = "StreetAddress";
    public const String Unstructured_Name                    = "UnstructuredName";
    public const String Unstructured_Address                 = "UnstructuredAddress";
    public const String Device_Serial_Number                 = "DeviceSerialNumber";
    public const String Extension_Request_ID                 = "ExtensionRequestId";
    public const String Extension_Name                       = "ExtensionName";
    public const String Extension_Flags                      = "ExtensionFlags";
    public const String Extension_Raw_Value                  = "ExtensionRawValue";
    public const String Attribute_Request_ID                 = "AttributeRequestId";
    public const String Attribute_Name                       = "AttributeName";
    public const String Attribute_Value                      = "AttributeValue";
    public const String CRL_Row_ID                           = "CRLRowId";
    public const String CRL_Number                           = "CRLNumber";
    public const String CRL_Min_Base                         = "CRLMinBase";
    public const String CRL_Name_Id                          = "CRLNameId";
    public const String CRL_Count                            = "CRLCount";
    public const String CRL_This_Update                      = "CRLThisUpdate";
    public const String CRL_Next_Update                      = "CRLNextUpdate";
    public const String CRL_This_Publish                     = "CRLThisPublish";
    public const String CRL_Next_Publish                     = "CRLNextPublish";
    public const String CRL_Effective                        = "CRLEffective";
    public const String CRL_Propagation_Complete             = "CRLPropagationComplete";
    public const String CRL_Last_Published                   = "CRLLastPublish";
    public const String CRL_Publish_Attempts                 = "CRLPublishAttempts";
    public const String CRL_Publish_Flags                    = "CRLPublishFlags";
    public const String CRL_Publish_Status_Code              = "CRLPublishStatusCode";
    public const String CRL_Publish_Error                    = "CRLPublishError";
    public const String CRL_Raw_CRL                          = "CRLRawCRL";
}
