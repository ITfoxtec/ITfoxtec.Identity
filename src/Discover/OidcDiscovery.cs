using Newtonsoft.Json;
using System.Collections.Generic;

namespace ITfoxtec.Identity.Discovery
{
    public class OidcDiscovery
    {
        /// <summary>
        /// REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier. If Issuer discovery is supported 
        /// (see OpenID Connect Discovery Section 2), this value MUST be identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value in 
        /// ID Tokens issued from this Issuer.
        /// </summary>
        [JsonProperty(PropertyName = "issuer")]
        public string Issuer { get; set; }

        /// <summary>
        /// REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
        /// </summary>
        [JsonProperty(PropertyName = "authorization_endpoint")]
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit Flow is used.
        /// </summary>
        [JsonProperty(PropertyName = "token_endpoint")]
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP [OpenID.SessionManagement].
        /// </summary>
        [JsonProperty(PropertyName = "end_session_endpoint")]
        public string EndSessionEndpoint { get; set; }

        /// <summary>
        /// REQUIRED. URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate signatures from the OP. The JWK Set MAY also contain 
        /// the Server's encryption key(s), which are used by RPs to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use) 
        /// parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage. Although some algorithms allow the same key to be used for 
        /// both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. 
        /// When used, the bare key values MUST still be present and MUST match those in the certificate.
        /// </summary>
        [JsonProperty(PropertyName = "jwks_uri")]
        public string JwksUri { get; set; }

        /// <summary>
        /// RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST support the openid scope value. 
        /// Servers MAY choose not to advertise some supported scope values even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
        /// </summary>
        [JsonProperty(PropertyName = "scopes_supported")]
        public IEnumerable<string> ScopesSupported { get; set; } = new [] { IdentityConstants.DefaultOidcScopes.OpenId };

        /// <summary>
        /// REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID Providers MUST support the code, id_token, 
        /// and the token id_token Response Type values.
        /// </summary>
        [JsonProperty(PropertyName = "response_types_supported")]
        public IEnumerable<string> ResponseTypesSupported { get; set; }

        /// <summary>
        /// OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices 
        /// [OAuth.Responses]. If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
        /// </summary>
        [JsonProperty(PropertyName = "response_modes_supported")]
        public IEnumerable<string> ResponseModesSupported { get; set; }

        /// <summary>
        /// REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include pairwise and public.
        /// </summary>
        [JsonProperty(PropertyName = "subject_types_supported")]
        public IEnumerable<string> SubjectTypesSupported { get; set; }

        /// <summary>
        /// REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT]. 
        /// The algorithm RS256 MUST be included. The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization 
        /// Endpoint (such as when using the Authorization Code Flow).
        /// </summary>
        [JsonProperty(PropertyName = "id_token_signing_alg_values_supported")]
        public IEnumerable<string> IdTokenSigningAlgValuesSupported { get; set; }

        /// <summary>
        /// RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for. Note that for privacy or other 
        /// reasons, this might not be an exhaustive list.
        /// </summary>
        [JsonProperty(PropertyName = "claims_supported")]
        public IEnumerable<string> ClaimsSupported { get; set; } = IdentityConstants.DefaultJwtClaims.AccessToken;
    }
}
