using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 Access Token Response and OIDC Token Response.
    /// </summary>
    public class TokenResponse : TokenBaseResponse
    {
        /// <summary>
        /// OIDC REQUIRED. OIDC ID Token value associated with the authenticated session.
        /// </summary>
        [JsonProperty(PropertyName = "id_token")]
        public string IdToken { get; set; }
    }
}
