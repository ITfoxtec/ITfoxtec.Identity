using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OIDC Front-Channel Logout Request.
    /// </summary>
    public class FrontChannelLogoutRequest
    {
        /// <summary>
        /// Issuer Identifier for the OP issuing the front-channel logout request.
        /// </summary>
        [JsonProperty(PropertyName = "iss")]
        public string Issuer { get; set; }

        /// <summary>
        /// Identifier for the Session.
        /// </summary>
        [JsonProperty(PropertyName = "sid")]
        public string SessionId { get; set; }
    }
}
