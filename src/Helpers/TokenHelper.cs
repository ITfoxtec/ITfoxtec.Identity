using ITfoxtec.Identity.Messages;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using ITfoxtec.Identity.Discovery;

namespace ITfoxtec.Identity.Helpers
{
    /// <summary>
    /// Token helpers.
    /// </summary>
    public class TokenHelper
    {
#if NET || NETCORE
        private readonly IHttpClientFactory httpClientFactory;
#else
        private readonly HttpClient httpClient;
#endif
        private readonly OidcDiscoveryHandler oidcDiscoveryHandler;

        /// <summary>
        /// Constructor.
        /// </summary>
        public TokenHelper(
#if NET || NETCORE
            IHttpClientFactory httpClientFactory,
#else
            HttpClient httpClient,
#endif
            OidcDiscoveryHandler oidcDiscoveryHandler)
        {
#if NET || NETCORE
            this.httpClientFactory = httpClientFactory;
#else
            this.httpClient = httpClient;
#endif
            this.oidcDiscoveryHandler = oidcDiscoveryHandler;
        }

        /// <summary>
        /// Get access token with client credential grant.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithClientCredentialGrantAsync(string clientId, string clientSecret, string scope = null)
        {
            if (clientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientId));
            if (clientSecret.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientSecret));

            var tokenEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).TokenEndpoint;
            return await GetAccessTokenWithClientCredentialGrantAsync(clientId, clientSecret, tokenEndpoint, scope.IsNullOrEmpty() ? null : new TokenRequest { Scope = scope });
        }

        /// <summary>
        /// Get access token with client credential grant.
        /// </summary>
        /// <typeparam name="Treq">Of the type TokenRequest.</typeparam>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="tokenEndpoint">The token endpoint.</param>
        /// <param name="tokenRequest">The token request.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithClientCredentialGrantAsync<Treq>(string clientId, string clientSecret, string tokenEndpoint, Treq tokenRequest = null) where Treq : TokenRequest
        {
            if (clientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientId));
            if (clientSecret.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientSecret));
            if (tokenEndpoint.IsNullOrEmpty()) throw new ArgumentNullException(nameof(tokenEndpoint));

            var accessTokenRequest = tokenRequest ?? new TokenRequest();
            accessTokenRequest.GrantType = IdentityConstants.GrantTypes.ClientCredentials;
            accessTokenRequest.ClientId = clientId;

            var clientCredentials = new ClientCredentials
            {
                ClientSecret = clientSecret,
            };

            var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
            var nameValueCollection = accessTokenRequest.ToDictionary().AddToDictionary(clientCredentials);
            request.Content = new FormUrlEncodedContent(nameValueCollection);

#if NET || NETCORE
            var httpClient = httpClientFactory.CreateClient();
#endif

            using (var response = await httpClient.SendAsync(request))
            {
                try
                {
                    var result = await response.Content.ReadAsStringAsync();

                    var tokenResponse = result.ToObject<TokenResponse>();
                    tokenResponse.Validate();
                    return (tokenResponse.AccessToken, tokenResponse.ExpiresIn);
                }
                catch (Exception ex)
                {
                    throw new ResponseException($"Error getting access token with client credentials. StatusCode={response.StatusCode}", ex);
                }
            }
        }
    }
}
