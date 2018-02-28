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
    }
}
