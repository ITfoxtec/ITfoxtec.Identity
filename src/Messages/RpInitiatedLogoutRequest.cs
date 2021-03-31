using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OIDC RP-Initiated Logout Request.
    /// </summary>
    public class RpInitiatedLogoutRequest
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

        /// <summary>
        /// OPTIONAL. End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. 
        /// For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada, then French (without region), followed by English (without region).
        /// </summary>
        [JsonProperty(PropertyName = "ui_locales")]
        public string UiLocales { get; set; }
    }
}
