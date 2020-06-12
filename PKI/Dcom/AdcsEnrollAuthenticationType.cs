﻿namespace SysadminsLV.PKI.Dcom {
    public enum AdcsEnrollAuthenticationType {
        /// <summary>
        /// Not used.
        /// </summary>
        None				= 0,
        /// <summary>
        /// Not used.
        /// </summary>
        Anonymous			= 1,
        /// <summary>
        /// Authentication is performed using Kerberos.
        /// </summary>
        Kerberos			= 2,
        /// <summary>
        /// Authentication is performed using user name and password combination.
        /// </summary>
        UserNameAndPassword = 4,
        /// <summary>
        /// Authentication is performed using client certificate.
        /// </summary>
        ClientCertificate = 8
    }
}