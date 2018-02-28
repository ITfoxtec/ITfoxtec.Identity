using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OIDC Authentication Response.
    /// </summary>
    public class AuthenticationResponse : AuthorizationResponse
    {
        /// <summary>
        /// OpenID Connect Implicit REQUIRED else OPTIONAL.
        /// </summary>
        [JsonProperty(PropertyName = "id_token")]
        public string IdToken { get; set; }

        /// <summary>
        /// OPTIONAL. OAuth 2.0 Access Token.
        /// </summary>
        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken { get; set; }

        /// <summary>
        /// REQUIRED. OAuth 2.0 Token Type value. The value MUST be Bearer or another token_type value that the Client has negotiated with the Authorization Server. 
        /// </summary>
        [JsonProperty(PropertyName = "token_type")]
        public string TokenType { get; set; }

        /// <summary>
        /// OPTIONAL. Expiration time of the Access Token in seconds since the response was generated.
        /// </summary>
        [JsonProperty(PropertyName = "expires_in")]
        public int ExpiresIn { get; set; }
    }
}
