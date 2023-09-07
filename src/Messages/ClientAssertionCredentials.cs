using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// Assertion Framework for OAuth 2.0 Client Authentication, Client Assertion in request.
    /// </summary>
    public class ClientAssertionCredentials
    {
        /// <summary>
        /// REQUIRED. The format of the assertion as defined by the authorization server.The value will be an absolute URI.
        /// </summary>
        [JsonProperty(PropertyName = "client_assertion_type")]
        public string ClientAssertionType { get; set; }

        /// <summary>
        /// REQUIRED. The assertion being used to authenticate the client. Specific serialization of the assertion is defined by profile documents.
        /// </summary>
        [JsonProperty(PropertyName = "client_assertion")]
        public string ClientAssertion { get; set; }
    }
}
