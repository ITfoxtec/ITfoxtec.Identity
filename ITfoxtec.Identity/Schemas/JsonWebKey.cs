﻿using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Schemas
{
    /// <summary>
    /// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. This specification also defines a JWK Set JSON data structure that represents 
    /// a set of JWKs. Cryptographic algorithms and identifiers for use with this specification are described in the separate JSON Web Algorithms (JWA) specification and IANA registries established 
    /// by that specification.
    /// </summary>
    public class JsonWebKey
    {
        /// <summary>
        /// The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC". "kty" values should either be registered in the IANA 
        /// "JSON Web Key Types" registry established by [JSON Web Algorithms (JWA)] or be a value that contains a Collision-Resistant Name. The "kty" value is a case-sensitive string. 
        /// This member MUST be present in a JWK.
        /// </summary>
        [JsonProperty(PropertyName = "kty")]
        public string KeyType { get; set; }

        /// <summary>
        /// The "use" (public key use) parameter identifies the intended use of the public key. The "use" parameter is employed to indicate whether a public key is used for encrypting data or 
        /// verifying the signature on data.
        /// </summary>
        [JsonProperty(PropertyName = "use")]
        public string PublicKeyUse { get; set; }

        /// <summary>
        /// The "key_ops" (key operations) parameter identifies the operation(s) for which the key is intended to be used. The "key_ops" parameter is intended for use cases in which public, private, 
        /// or symmetric keys may be present. Its value is an array of key operation values.
        /// </summary>
        [JsonProperty(PropertyName = "key_ops")]
        public IEnumerable<string> KeyOperations { get; set; }

        /// <summary>
        /// The "alg" (algorithm) parameter identifies the algorithm intended for use with the key. The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" 
        /// registry established by [JSON Web Algorithms (JWA)] or be a value that contains a Collision-Resistant Name. The "alg" value is a case-sensitive ASCII string. Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "alg")]
        public string Algorithm { get; set; }

        /// <summary>
        /// The "kid" (key ID) parameter is used to match a specific key. 
        /// </summary>
        [JsonProperty(PropertyName = "kid")]
        public string KeyId { get; set; }

        /// <summary>
        /// The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280]. Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "x5u")]
        public string X509Uri { get; set; }

        /// <summary>
        /// The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates[RFC5280]. The certificate chain is represented as a JSON array of certificate value strings.
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "x5c")]
        public IEnumerable<string> X509CertificateChain { get; set; }

        /// <summary>
        /// The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280]. 
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "x5t")]
        public string X509CertificateSHA1Thumbprint { get; set; }

        /// <summary>
        /// The "x5t" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280]. 
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "x5t#S256")]
        public string X509CertificateSHA256Thumbprint { get; set; }

        /// <summary>
        /// The modulus member contains the modulus value for the RSA public key. It is represented as the base64url encoding of the value's big endian representation.
        /// </summary>
        [JsonProperty(PropertyName = "n")]
        public string Modulus { get; set; }

        /// <summary>
        /// The exponent member contains the exponent value for the RSA public key. It is represented as the base64url encoding of the value's big endian representation.
        /// </summary>
        [JsonProperty(PropertyName = "e")]
        public string Exponent { get; set; }

        public JsonWebKey(X509Certificate2 certificate)
        {
            KeyType = IdentityConstants.JsonWebKeyTypes.RSA;

            var securityKey = new X509SecurityKey(certificate);
            KeyId = securityKey.KeyId;
            X509CertificateChain = new[] { Convert.ToBase64String(certificate.RawData) };
            X509CertificateSHA1Thumbprint = WebEncoders.Base64UrlEncode(certificate.GetCertHash());

            var parameters = (securityKey.PublicKey as RSA).ExportParameters(false);
            Modulus = WebEncoders.Base64UrlEncode(parameters.Modulus);
            Exponent = WebEncoders.Base64UrlEncode(parameters.Exponent);
        }
    }
}
