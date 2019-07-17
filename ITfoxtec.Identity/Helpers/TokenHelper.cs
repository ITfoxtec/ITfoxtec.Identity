﻿using Microsoft.Extensions.DependencyInjection;
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
        private readonly IServiceProvider serviceProvider;

        /// <summary>
        /// Constructor.
        /// </summary>
        public TokenHelper(IServiceProvider serviceProvider)
        {
            this.serviceProvider = serviceProvider;
        }

        /// <summary>
        /// Get access token with client credentials.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int)> GetAccessTokenWithClientCredentialsAsync(string clientId, string clientSecret, string redirectUri, string scope = null)
        {
            if (clientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientId));
            if (clientSecret.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientSecret));
            if (redirectUri.IsNullOrEmpty()) throw new ArgumentNullException(nameof(redirectUri));

            var oidcDiscoveryHandler = serviceProvider.GetService<OidcDiscoveryHandler>();
            if (oidcDiscoveryHandler == null) new Exception($"Unable to resolve {nameof(OidcDiscoveryHandler)}.");

            var tokenEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).TokenEndpoint;
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

        /// <summary>
        /// Get access token with client credentials.
        /// </summary>
        /// <typeparam name="Treq">Of the type TokenRequest.</typeparam>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="tokenEndpoint">The token endpoint.</param>
        /// <param name="tokenRequest">The token request.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int)> GetAccessTokenWithClientCredentialsAsync<Treq>(string clientId, string clientSecret, string tokenEndpoint, Treq tokenRequest = null) where Treq : TokenRequest
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
           
            var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();
            if (httpClientFactory == null) new Exception($"Unable to resolve {nameof(IHttpClientFactory)}.");

            using (var response = await httpClientFactory.CreateClient().SendAsync(request))
            {
                var result = await response.Content.ReadAsStringAsync();

                var tokenResponse = result.ToObject<TokenResponse>();
                tokenResponse.Validate();

                if (tokenResponse.AccessToken.IsNullOrEmpty())
                {
                    throw new ResponseException($"Error getting access token with client credentials. StatusCode={response.StatusCode}");
                }

                return (tokenResponse.AccessToken, tokenResponse.ExpiresIn);
            }
        }
    }
}
