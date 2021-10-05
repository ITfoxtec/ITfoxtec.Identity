using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 Access Token Response and OIDC Token Response.
    /// </summary>
    public class TokenResponse : IErrorResponse
    {
        /// <summary>
        /// OIDC REQUIRED. OIDC ID Token value associated with the authenticated session.
        /// </summary>
        [JsonProperty(PropertyName = "id_token")]
        public string IdToken { get; set; }

        /// <summary>
        /// OAuth 2.0 REQUIRED. OAuth 2.0 Access Token.
        /// OIDC OPTIONAL. 
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
        public int? ExpiresIn { get; set; }

        /// <summary>
        /// OPTIONAL. OAuth 2.0 refresh token.
        /// </summary>
        [JsonProperty(PropertyName = "refresh_token")]
        public string RefreshToken { get; set; }

        /// <summary>
        /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The scope of the access token as described by OAuth 2.0 Section 3.3.
        /// </summary>
        [JsonProperty(PropertyName = "scope")]
        public string Scope { get; set; }

        #region Error
        /// <summary>
        /// If error REQUIRED. A single ASCII [USASCII] error code.
        /// </summary>
        [JsonProperty(PropertyName = "error")]
        public string Error { get; set; }

        /// <summary>
        /// If error OPTIONAL. Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred.
        /// </summary>
        [JsonProperty(PropertyName = "error_description")]
        public string ErrorDescription { get; set; }

        /// <summary>
        /// If error OPTIONAL. A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error.
        /// </summary>
        [JsonProperty(PropertyName = "error_uri")]
        public string ErrorUri { get; set; }
        #endregion
    }
}
