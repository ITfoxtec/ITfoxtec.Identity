using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OIDC Session Response.
    /// </summary>
    public class SessionResponse 
    {
        /// <summary>
        /// REQUIRED if session management is supported. Represents the End-User's login state at the OP. It MUST NOT contain the space (" ") character. This value is opaque to the RP. 
        /// </summary>
        [JsonProperty(PropertyName = "session_state")]
        public string SessionState { get; set; }
    }
}
