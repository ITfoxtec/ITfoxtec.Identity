using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OIDC End Session Response.
    /// </summary>
    public class EndSessionResponse
    {
        /// <summary>
        ///  OPTIONAL. Opaque value used by the RP to maintain state between the logout request and the callback to the endpoint specified by the post_logout_redirect_uri query parameter.
        ///  If included in the logout request, the OP passes this value back to the RP using the state query parameter when redirecting the User Agent back to the RP.
        /// </summary>
        [JsonProperty(PropertyName = "state")]
        public string State { get; set; }
    }
}
