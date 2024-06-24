using System.Net.Http.Headers;
using System.Net.Http;
using System;

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
            if(token.IsNullOrEmpty()) throw new ArgumentNullException(nameof(token));

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(IdentityConstants.TokenTypes.Bearer, token);
        }

        /// <summary>
        /// Set authorization header client credential basic.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        public static void SetAuthorizationHeaderClientCredentialBasic(this HttpClient client, string clientId, string clientSecret)
        {
            if (clientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientId));
            if (clientSecret.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientSecret));

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(IdentityConstants.BasicAuthentication.Basic, $"{clientId.OAuthUrlEncode()}:{clientSecret.OAuthUrlEncode()}".Base64Encode());
        }
    }
}
