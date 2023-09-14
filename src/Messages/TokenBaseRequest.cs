using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 Token Base Request.
    /// </summary>
    public abstract class TokenBaseRequest
    {
        /// <summary>
        /// REQUIRED. OAuth 2.0 Grant Type value that determines the method used by the client to request authorization and the types supported by the authorization server.
        /// </summary>
        [JsonProperty(PropertyName = "grant_type")]
        public string GrantType { get; set; }

        /// <summary>
        /// OPTIONAL. The scope is a list of space-delimited, case-sensitive strings, as defined in OAuth 2.0 Section 3.3.
        /// </summary>
        [JsonProperty(PropertyName = "scope")]
        public string Scope { get; set; }
    }
}
