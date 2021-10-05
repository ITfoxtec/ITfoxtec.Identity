﻿using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 [RFC8693] Token Exchange Response.
    /// </summary>
    public class TokenExchangeResponse : IErrorResponse
    {
        /// <summary>
        /// REQUIRED. The security token issued by the authorization server in response to the token exchange request.
        /// </summary>
        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken { get; set; }

        /// <summary>
        /// REQUIRED. An identifier, as described in Section 3, for the representation of the issued security token.
        /// </summary>
        [JsonProperty(PropertyName = "issued_token_type")]
        public string IssuedTokenType { get; set; }

        /// <summary>
        /// REQUIRED. A case-insensitive value specifying the method of using the access token issued, as specified in Section 7.1 of[RFC6749].
        /// </summary>
        [JsonProperty(PropertyName = "token_type")]
        public string TokenType { get; set; }

        /// <summary>
        ///  RECOMMENDED. The validity lifetime, in seconds, of the token issued by the authorization server.
        /// </summary>
        [JsonProperty(PropertyName = "expires_in")]
        public int? ExpiresIn { get; set; }

        /// <summary>
        ///  OPTIONAL if the scope of the issued security token is identical to the scope requested by the client; otherwise, it is REQUIRED.
        /// </summary>
        [JsonProperty(PropertyName = "scope")]
        public string Scope { get; set; } 

        /// <summary>
        /// OPTIONAL. A refresh token will typically not be issued when the exchange is of one temporary credential (the subject_token) for a different temporary credential (the issued token) for 
        /// use in some other context.  A refresh token can be issued in cases where the client of the token exchange needs the ability to access a resource even when the original credential is 
        /// no longer valid (e.g., user-not-present or offline scenarios where there is no longer any user entertaining an active session with the client).
        /// </summary>
        [JsonProperty(PropertyName = "refresh_token")]
        public string RefreshToken { get; set; }

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
