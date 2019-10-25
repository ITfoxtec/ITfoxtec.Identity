using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    public class CodeVerifierSecret
    {
        /// <summary>
        /// A cryptographically random string that is used to correlate the authorization request to the token request.
        /// </summary>
        [JsonProperty(PropertyName = "code_verifier")]
        public string CodeVerifier { get; set; }
    }
}
