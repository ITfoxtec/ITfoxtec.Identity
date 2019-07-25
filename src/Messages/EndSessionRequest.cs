using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OIDC End Session Request.
    /// </summary>
    public class EndSessionRequest
    {
        /// <summary>
        /// RECOMMENDED. Previously issued ID Token passed to the logout endpoint as a hint about the End-User's current authenticated session with the Client. 
        /// This is used as an indication of the identity of the End-User that the RP is requesting be logged out by the OP.
        /// </summary>
        [JsonProperty(PropertyName = "id_token_hint")]
        public string IdTokenHint { get; set; }

        /// <summary>
        /// OPTIONAL. URL to which the RP is requesting that the End-User's User Agent be redirected after a logout has been performed. The value MUST have been 
        /// previously registered with the OP.
        /// </summary>
        [JsonProperty(PropertyName = "post_logout_redirect_uri")]
        public string PostLogoutRedirectUri { get; set; }

        /// <summary>
        ///  OPTIONAL. Opaque value used by the RP to maintain state between the logout request and the callback to the endpoint specified by the post_logout_redirect_uri query parameter.
        ///  If included in the logout request, the OP passes this value back to the RP using the state query parameter when redirecting the User Agent back to the RP.
        /// </summary>
        [JsonProperty(PropertyName = "state")]
        public string State { get; set; }
    }
}
