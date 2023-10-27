using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 [RFC8693] Token Exchange Response.
    /// </summary>
    public class TokenExchangeResponse : TokenBaseResponse
    {
        /// <summary>
        /// REQUIRED. An identifier, as described in Section 3, for the representation of the issued security token.
        /// </summary>
        [JsonProperty(PropertyName = "issued_token_type")]
        public string IssuedTokenType { get; set; }
    }
}
