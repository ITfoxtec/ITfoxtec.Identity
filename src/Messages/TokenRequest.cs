using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 Access Token Request and OIDC Token Request.
    /// </summary>
    public class TokenRequest : TokenBaseRequest
    {
        /// <summary>
        /// REQUIRED in Authorization Code Grant. The authorization code received from the authorization server.
        /// </summary>
        [JsonProperty(PropertyName = "code")]
        public string Code { get; set; }

        /// <summary>
        /// REQUIRED in Refresh Token Grant. The refresh token issued to the client.
        /// </summary>
        [JsonProperty(PropertyName = "refresh_token")]
        public string RefreshToken { get; set; }
       
        /// <summary>
        ///  REQUIRED, if the "redirect_uri" parameter was included in the authorization request.
        /// </summary>
        [JsonProperty(PropertyName = "redirect_uri")]
        public string RedirectUri { get; set; }

        /// <summary>
        /// REQUIRED, if the client is not authenticating with the authorization server as described in OAuth 2.0 Section 3.2.1.
        /// </summary>
        [JsonProperty(PropertyName = "client_id")]
        public string ClientId { get; set; }

        /// <summary>
        /// REQUIRED in Resource Owner Password Credentials Grant. The resource owner username.
        /// </summary>
        [JsonProperty(PropertyName = "username")]
        public string Username { get; set; }

        /// <summary>
        /// REQUIRED in Resource Owner Password Credentials Grant. The resource owner password.
        /// </summary>
        [JsonProperty(PropertyName = "password")]
        public string Password { get; set; }
    }
}
