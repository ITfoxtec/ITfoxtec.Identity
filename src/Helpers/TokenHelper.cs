using MSTokens = Microsoft.IdentityModel.Tokens;
using ITfoxtec.Identity.Messages;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using ITfoxtec.Identity.Discovery;
using ITfoxtec.Identity.Models;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Helpers
{
    /// <summary>
    /// Token helpers.
    /// </summary>
    public class TokenHelper : TokenExecuteHelper
    {
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
            OidcDiscoveryHandler oidcDiscoveryHandler) : base (
#if NET || NETCORE
            httpClientFactory)
#else
            httpClient)
#endif
        {
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
            var tokenResponse = await ExecuteTokenRequestWithClientCredentialGrantAsync<TokenRequest, TokenResponse>(clientId, clientSecret, tokenEndpoint, tokenRequest: scope.IsNullOrEmpty() ? null : new TokenRequest { GrantType = IdentityConstants.GrantTypes.ClientCredentials, Scope = scope });
            return (tokenResponse.AccessToken, tokenResponse.ExpiresIn);
        }

        /// <summary>
        /// Get access token with assertion in client credential grant.
        /// </summary>
        /// <param name="jsonWebClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="clientAssertionExpiresIn">The client assertion expires in.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithAssertionClientCredentialGrantAsync(JsonWebKey jsonWebClientKey, string clientId, string scope = null, int clientAssertionExpiresIn = 30)
        {
            if (jsonWebClientKey == null) throw new ArgumentNullException(nameof(jsonWebClientKey));

            var tokenEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).TokenEndpoint;
            var tokenResponse = await ExecuteTokenRequestWithAssertionClientCredentialGrantAsync<TokenRequest, TokenResponse>(jsonWebClientKey.ToSecurityKey(), clientId, tokenEndpoint, tokenRequest: scope.IsNullOrEmpty() ? null : new TokenRequest { GrantType = IdentityConstants.GrantTypes.ClientCredentials, Scope = scope }, clientAssertionExpiresIn);
            return (tokenResponse.AccessToken, tokenResponse.ExpiresIn);
        }

        /// <summary>
        /// Get access token with assertion in client credential grant.
        /// </summary>
        /// <param name="certificateClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="clientAssertionExpiresIn">The client assertion expires in.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithAssertionClientCredentialGrantAsync(X509Certificate2 certificateClientKey, string clientId, string scope = null, int clientAssertionExpiresIn = 30)
        {
            if (certificateClientKey == null) throw new ArgumentNullException(nameof(certificateClientKey));

            var tokenEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).TokenEndpoint;
            var tokenResponse = await ExecuteTokenRequestWithAssertionClientCredentialGrantAsync<TokenRequest, TokenResponse>(certificateClientKey, clientId, tokenEndpoint, tokenRequest: scope.IsNullOrEmpty() ? null : new TokenRequest { GrantType = IdentityConstants.GrantTypes.ClientCredentials, Scope = scope }, clientAssertionExpiresIn);
            return (tokenResponse.AccessToken, tokenResponse.ExpiresIn);
        }

        /// <summary>
        /// Get access token with assertion in client credential grant.
        /// </summary>
        /// <param name="securityClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="clientAssertionExpiresIn">The client assertion expires in.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithAssertionClientCredentialGrantAsync(MSTokens.SecurityKey securityClientKey, string clientId, string scope = null, int clientAssertionExpiresIn = 30)
        {
            var tokenEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).TokenEndpoint;
            var tokenResponse = await ExecuteTokenRequestWithAssertionClientCredentialGrantAsync<TokenRequest, TokenResponse>(securityClientKey, clientId, tokenEndpoint, tokenRequest: scope.IsNullOrEmpty() ? null : new TokenRequest { GrantType = IdentityConstants.GrantTypes.ClientCredentials, Scope = scope }, clientAssertionExpiresIn);
            return (tokenResponse.AccessToken, tokenResponse.ExpiresIn);
        }
    }
}
