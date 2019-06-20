using Microsoft.Extensions.DependencyInjection;
using ITfoxtec.Identity.Messages;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using ITfoxtec.Identity.Discovery;

namespace ITfoxtec.Identity.Helpers
{
    public class TokenHelper
    {
        private readonly IServiceProvider serviceProvider;

        public TokenHelper(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        public async Task<string> GetAccessTokenWithClientCredentialsAsync(string clientId, string clientSecret, string redirectUri, string scope = null)
        {
            if (clientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientId));
            if (clientSecret.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientSecret));
            if (redirectUri.IsNullOrEmpty()) throw new ArgumentNullException(nameof(redirectUri));

            var tokenEndpoint = (await serviceProvider.GetService<OidcDiscoveryHandler>().GetOidcDiscoveryAsync()).TokenEndpoint;
            var accessTokenRequest = new TokenRequest
            {
                RedirectUri = redirectUri,
            };
            if (!scope.IsNullOrEmpty())
            {
                accessTokenRequest.Scope = scope;
            }
            return await GetAccessTokenWithClientCredentialsAsync(clientId, clientSecret, tokenEndpoint, accessTokenRequest);
        }

        public async Task<string> GetAccessTokenWithClientCredentialsAsync<Treq>(string clientId, string clientSecret, string tokenEndpoint, Treq tokenRequest = null) where Treq : TokenRequest
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

            var client = serviceProvider.GetService<IHttpClientFactory>().CreateClient();
            using (var response = await client.SendAsync(request))
            {
                var result = await response.Content.ReadAsStringAsync();

                var tokenResponse = result.ToObject<TokenResponse>();
                tokenResponse.Validate();

                if (tokenResponse.AccessToken.IsNullOrEmpty())
                {
                    throw new ResponseException($"Error getting access token with client credentials. StatusCode={response.StatusCode}");
                }

                return tokenResponse.AccessToken;
            }
        }
    }
}
