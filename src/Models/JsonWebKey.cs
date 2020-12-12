using Newtonsoft.Json;
using System.Collections.Generic;

namespace ITfoxtec.Identity.Models
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
        public string Kty { get; set; }

        /// <summary>
        /// The "use" (public key use) parameter identifies the intended use of the public key. The "use" parameter is employed to indicate whether a public key is used for encrypting data or 
        /// verifying the signature on data.
        /// </summary>
        [JsonProperty(PropertyName = "use")]
        public string Use { get; set; }

        /// <summary>
        /// The "key_ops" (key operations) parameter identifies the operation(s) for which the key is intended to be used. The "key_ops" parameter is intended for use cases in which public, private, 
        /// or symmetric keys may be present. Its value is an array of key operation values.
        /// </summary>
        [JsonProperty(PropertyName = "key_ops")]
        public IList<string> KeyOps { get; set; }

        /// <summary>
        /// The "alg" (algorithm) parameter identifies the algorithm intended for use with the key. The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms" 
        /// registry established by [JSON Web Algorithms (JWA)] or be a value that contains a Collision-Resistant Name. The "alg" value is a case-sensitive ASCII string. Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "alg")]
        public string Alg { get; set; }

        /// <summary>
        /// The "kid" (key ID) parameter is used to match a specific key. 
        /// </summary>
        [JsonProperty(PropertyName = "kid")]
        public string Kid { get; set; }

        /// <summary>
        /// The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280]. Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "x5u")]
        public string X5u { get; set; }

        /// <summary>
        /// The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates[RFC5280]. The certificate chain is represented as a JSON array of certificate value strings.
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "x5c")]
        public IList<string> X5c { get; set; }

        /// <summary>
        /// The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280]. 
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "x5t")]
        public string X5t { get; set; }

        /// <summary>
        /// The "x5t" (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280]. 
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "x5t#S256")]
        public string X5tS256 { get; set; }

        /// <summary>
        /// The modulus member contains the modulus value for the RSA public key. It is represented as the base64url encoding of the value's big endian representation.
        /// </summary>
        [JsonProperty(PropertyName = "n")]
        public string N { get; set; }

        /// <summary>
        /// The exponent member contains the exponent value for the RSA public key. It is represented as the base64url encoding of the value's big endian representation.
        /// </summary>
        [JsonProperty(PropertyName = "e")]
        public string E { get; set; }

        /// <summary>
        /// The exponent member contains the private exponent value for the RSA private key.It is represented as the base64url encoding of the value's unsigned big endian 
        /// representation as a byte array.
        /// </summary>
        [JsonProperty(PropertyName = "d")]
        public string D { get; set; }

        /// <summary>
        /// The exponent member contains the first prime factor, a positive integer. It is represented as the base64url encoding of the value's unsigned big endian 
        /// representation as a byte array.
        /// </summary>
        [JsonProperty(PropertyName = "p")]
        public string P { get; set; }

        /// <summary>
        /// The exponent member contains the second prime factor, a positive integer.It is represented as the base64url encoding of the value's unsigned big endian 
        /// representation as a byte array.
        /// </summary>
        [JsonProperty(PropertyName = "q")]
        public string Q { get; set; }

        /// <summary>
        /// The exponent member contains the Chinese Remainder Theorem(CRT) exponent of the first factor, a positive integer.It is represented as the base64url encoding 
        /// of the value's unsigned big endian representation as a byte array.
        /// </summary>
        [JsonProperty(PropertyName = "dp")]
        public string DP { get; set; }

        /// <summary>
        /// The exponent member contains the Chinese Remainder Theorem(CRT) exponent of the second factor, a positive integer.It is represented as the base64url encoding 
        /// of the value's unsigned big endian representation as a byte array.
        /// </summary>
        [JsonProperty(PropertyName = "dq")]
        public string DQ { get; set; }

        /// <summary>
        /// The exponent member contains the Chinese Remainder Theorem(CRT) coefficient of the second factor, a positive integer.It is represented as the base64url encoding 
        /// of the value's unsigned big endian representation as a byte array.
        /// </summary>
        [JsonProperty(PropertyName = "qi")]
        public string QI { get; set; }
    }
}
