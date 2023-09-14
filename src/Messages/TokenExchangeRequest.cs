using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 [RFC8693] Token Exchange Request.
    /// </summary>
    public class TokenExchangeRequest : TokenBaseRequest
    {
        public TokenExchangeRequest()
        {
            GrantType = IdentityConstants.GrantTypes.TokenExchange;
        }

        /// <summary>
        ///  OPTIONAL. A URI that indicates the target service or resource where the client intends to use the requested security token.
        /// </summary>
        [JsonProperty(PropertyName = "resource")]
        public string Resource { get; set; }

        /// <summary>
        /// OPTIONAL. The logical name of the target service where the client intends to use the requested security token.
        /// </summary>
        [JsonProperty(PropertyName = "audience")]
        public string Audience { get; set; }

        /// <summary>
        /// OPTIONAL. An identifier, as described in Section 3, for the type of the requested security token.
        /// </summary>
        [JsonProperty(PropertyName = "requested_token_type")]
        public string RequestedTokenType { get; set; }

        /// <summary>
        /// REQUIRED. A security token that represents the identity of the party on behalf of whom the request is being made.
        /// </summary>
        [JsonProperty(PropertyName = "subject_token")]
        public string SubjectToken { get; set; }

        /// <summary>
        /// REQUIRED. An identifier, as described in Section 3, that indicates the type of the security token in the "subject_token" parameter.
        /// </summary>
        [JsonProperty(PropertyName = "subject_token_type")]
        public string SubjectTokenType { get; set; }

        /// <summary>
        /// OPTIONAL. A security token that represents the identity of the acting party.
        /// </summary>
        [JsonProperty(PropertyName = "actor_token")]
        public string ActorToken { get; set; }

        /// <summary>
        /// An identifier, as described in Section 3, that indicates the type of the security token in the "actor_token" parameter.  This is REQUIRED when the "actor_token" parameter is present in 
        /// the request but MUST NOT be included otherwise.
        /// </summary>
        [JsonProperty(PropertyName = "actor_token_type")]
        public string ActorTokenType { get; set; }
    }
}
