using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// OAuth 2.0 Client Credentials in request.
    /// </summary>
    public class ClientCredentials
    {
        /// <summary>
        /// REQUIRED. The client secret. The client MAY omit the parameter if the client secret is an empty string.
        /// </summary>
        [JsonProperty(PropertyName = "client_secret")]
        public string ClientSecret { get; set; }
    }
}
