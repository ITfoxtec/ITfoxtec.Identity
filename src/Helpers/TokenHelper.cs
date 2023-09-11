using MSTokens = Microsoft.IdentityModel.Tokens;
using ITfoxtec.Identity.Messages;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using ITfoxtec.Identity.Discovery;
using ITfoxtec.Identity.Models;
using System.Security.Claims;
using ITfoxtec.Identity.Tokens;
using System.Collections.Generic;
using System.Diagnostics.SymbolStore;
using System.Security.Cryptography.X509Certificates;

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

        /// <summary>
        /// Get access token with client assertion grant.
        /// </summary>
        /// <param name="securityClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithClientAssertionGrantAsync(MSTokens.SecurityKey securityClientKey, string clientId, string scope = null, int clientAssertionExpiresIn = 30)
        {
            var tokenEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).TokenEndpoint;
            return await GetAccessTokenWithClientAssertionGrantAsync(securityClientKey, clientId, tokenEndpoint, scope.IsNullOrEmpty() ? null : new TokenRequest { Scope = scope }, clientAssertionExpiresIn);
        }

        /// <summary>
        /// Get access token with client assertion grant.
        /// </summary>
        /// <param name="jsonWebClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithClientAssertionGrantAsync(JsonWebKey jsonWebClientKey, string clientId, string scope = null, int clientAssertionExpiresIn = 30)
        {
            if (jsonWebClientKey == null) throw new ArgumentNullException(nameof(jsonWebClientKey));

            var tokenEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).TokenEndpoint;
            return await GetAccessTokenWithClientAssertionGrantAsync(jsonWebClientKey.ToSecurityKey(), clientId, tokenEndpoint, scope.IsNullOrEmpty() ? null : new TokenRequest { Scope = scope }, clientAssertionExpiresIn);
        }

        /// <summary>
        /// Get access token with client assertion grant.
        /// </summary>
        /// <param name="certificateClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithClientAssertionGrantAsync(X509Certificate2 certificateClientKey, string clientId, string scope = null, int clientAssertionExpiresIn = 30)
        {
            if (certificateClientKey == null) throw new ArgumentNullException(nameof(certificateClientKey));

            var tokenEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).TokenEndpoint;
            return await GetAccessTokenWithClientAssertionGrantAsync(new MSTokens.X509SecurityKey(certificateClientKey), clientId, tokenEndpoint, scope.IsNullOrEmpty() ? null : new TokenRequest { Scope = scope }, clientAssertionExpiresIn);
        }

        /// <summary>
        /// Get access token with client assertion grant.
        /// </summary>
        /// <typeparam name="Treq">Of the type TokenRequest.</typeparam>
        /// <param name="securityClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="tokenEndpoint">The token endpoint.</param>
        /// <param name="tokenRequest">The token request.</param>
        /// <returns>The access token and expires in.</returns>
        public async Task<(string, int?)> GetAccessTokenWithClientAssertionGrantAsync<Treq>(MSTokens.SecurityKey securityClientKey, string clientId, string tokenEndpoint, Treq tokenRequest = null, int clientAssertionExpiresIn = 30) where Treq : TokenRequest
        {
            if (securityClientKey == null) throw new ArgumentNullException(nameof(securityClientKey));
            if (clientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientId));
            if (tokenEndpoint.IsNullOrEmpty()) throw new ArgumentNullException(nameof(tokenEndpoint));

            var accessTokenRequest = tokenRequest ?? new TokenRequest();
            accessTokenRequest.GrantType = IdentityConstants.GrantTypes.ClientCredentials;
            accessTokenRequest.ClientId = clientId;

            var clientAssertionClaims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, clientId),
                new Claim(JwtClaimTypes.JwtId, Guid.NewGuid().ToString())
            };

            string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256;
            var key = securityClientKey is MSTokens.JsonWebKey jsonWebKey ? jsonWebKey.ToSecurityKey() : securityClientKey;
            var token = JwtHandler.CreateToken(key, clientId, tokenEndpoint, clientAssertionClaims, expiresIn: clientAssertionExpiresIn, algorithm: algorithm);
            var clientAssertionCredentials = new ClientAssertionCredentials
            {
                ClientAssertionType = IdentityConstants.ClientAssertionTypes.JwtBearer,
                ClientAssertion = await token.ToJwtString()
            };

            var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
            var nameValueCollection = accessTokenRequest.ToDictionary().AddToDictionary(clientAssertionCredentials);
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
