using System.Net.Http.Headers;
using System.Net.Http;

namespace ITfoxtec.Identity
{
    public static class HttpClientExtensions
    {
        /// <summary>
        /// Set authorization header bearer token.
        /// </summary>
        /// <param name="token">The access token.</param>
        public static void SetAuthorizationHeaderBearer(this HttpClient client, string token)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(IdentityConstants.TokenTypes.Bearer, token);
        }
    }
}
