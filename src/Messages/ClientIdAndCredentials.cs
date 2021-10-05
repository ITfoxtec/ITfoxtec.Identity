using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 Client ID and Client Credentials in request.
    /// </summary>
    public class ClientIdAndCredentials
    {
        /// <summary>
        /// REQUIRED, if the client is not authenticating with the authorization server as described in OAuth 2.0 Section 3.2.1.
        /// </summary>
        [JsonProperty(PropertyName = "client_id")]
        public string ClientId { get; set; }

        /// <summary>
        /// REQUIRED. The client secret. The client MAY omit the parameter if the client secret is an empty string.
        /// </summary>
        [JsonProperty(PropertyName = "client_secret")]
        public string ClientSecret { get; set; }
    }
}
