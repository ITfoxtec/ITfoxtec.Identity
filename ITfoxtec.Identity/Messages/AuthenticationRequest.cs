using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OIDC Authentication Request.
    /// </summary>
    public class AuthenticationRequest : AuthorizationRequest
    {
        /// <summary>
        /// OPTIONAL. Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint. This use of this parameter is 
        /// NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type.
        /// </summary>
        [JsonProperty(PropertyName = "response_mode")]
        public string ResponseMode { get; set; }

        /// <summary>
        /// OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks. 
        /// REQUIRED in Authentication using the Implicit Flow.
        /// </summary>
        [JsonProperty(PropertyName = "nonce")]
        public string Nonce { get; set; }

        /// <summary>
        /// OPTIONAL. ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
        /// </summary>
        [JsonProperty(PropertyName = "display")]
        public string Display { get; set; }

        /// <summary>
        /// OPTIONAL. Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication 
        /// and consent. 
        /// </summary>
        [JsonProperty(PropertyName = "prompt")]
        public string Prompt { get; set; }

        /// <summary>
        /// OPTIONAL. Maximum Authentication Age. Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP. 
        /// If the elapsed time is greater than this value, the OP MUST attempt to actively re-authenticate the End-User.
        /// </summary>
        [JsonProperty(PropertyName = "max_age")]
        public int? MaxAge { get; set; }

        /// <summary>
        /// OPTIONAL. End-User's preferred languages and scripts for the user interface, represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference. 
        /// For instance, the value "fr-CA fr en" represents a preference for French as spoken in Canada, then French (without region), followed by English (without region).
        /// </summary>
        [JsonProperty(PropertyName = "ui_locales")]
        public string UiLocales { get; set; }

        /// <summary>
        /// OPTIONAL. ID Token previously issued by the Authorization Server being passed as a hint about the End-User's current or past authenticated session with the Client. 
        /// If the End-User identified by the ID Token is logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise, 
        /// it SHOULD return an error, such as login_required. 
        /// </summary>
        [JsonProperty(PropertyName = "id_token_hint")]
        public string IdTokenHint { get; set; }

        /// <summary>
        /// OPTIONAL. Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary). This hint can be used by an RP if it first
        /// asks the End-User for their e-mail address(or other identifier) and then wants to pass that value as a hint to the discovered authorization service.
        /// </summary>
        [JsonProperty(PropertyName = "login_hint")]
        public string LoginHint { get; set; }

        /// <summary>
        /// OPTIONAL. Requested Authentication Context Class Reference values.Space-separated string that specifies the acr values that the Authorization Server is being requested 
        /// to use for processing this Authentication Request, with the values appearing in order of preference.
        /// </summary>
        [JsonProperty(PropertyName = "acr_values")]
        public string AcrValues { get; set; }
    }
}
