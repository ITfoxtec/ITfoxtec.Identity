using MSTokens = Microsoft.IdentityModel.Tokens;
using ITfoxtec.Identity.Messages;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using ITfoxtec.Identity.Models;
using System.Security.Claims;
using ITfoxtec.Identity.Tokens;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Helpers
{
    /// <summary>
    /// Token helpers base.
    /// </summary>
    public class TokenExecuteHelper
    {
#if NET || NETCORE
        private readonly IHttpClientFactory httpClientFactory;
#else
        private readonly HttpClient httpClient;
#endif

        /// <summary>
        /// Constructor.
        /// </summary>
        public TokenExecuteHelper(
#if NET || NETCORE
            IHttpClientFactory httpClientFactory)
#else
            HttpClient httpClient)
#endif
        {
#if NET || NETCORE
            this.httpClientFactory = httpClientFactory;
#else
            this.httpClient = httpClient;
#endif
        }

        /// <summary>
        /// Get access token with client credential grant.
        /// </summary>
        /// <typeparam name="Treq">Of the type TokenBaseRequest.</typeparam>
        /// <typeparam name="Tres">Of the type TokenBaseResponse.</typeparam>
        /// <param name="clientId">The client id.</param>
        /// <param name="clientSecret">The client secret.</param>
        /// <param name="tokenEndpoint">The token endpoint.</param>
        /// <param name="tokenRequest">The token request.</param>
        /// <returns>The <typeparam>Tres</typeparam> token response.</returns>
        public async Task<Tres> ExecuteTokenRequestWithClientCredentialGrantAsync<Treq, Tres>(string clientId, string clientSecret, string tokenEndpoint, Treq tokenRequest = null) where Treq : TokenBaseRequest, new() where Tres : TokenBaseResponse
        {
            if (clientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientId));
            if (clientSecret.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientSecret));
            if (tokenEndpoint.IsNullOrEmpty()) throw new ArgumentNullException(nameof(tokenEndpoint));

            if (tokenRequest == null)
            {
                tokenRequest = new Treq();
            }

            if (tokenRequest is TokenRequest tr)
            {
                tr.ClientId = clientId;
            }

            var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
            var nameValueCollection = tokenRequest.ToDictionary();
            if (tokenRequest is TokenRequest)
            {
                nameValueCollection = nameValueCollection.AddToDictionary(new ClientCredentials
                {
                    ClientSecret = clientSecret,
                });
            }
            else
            {
                nameValueCollection = nameValueCollection.AddToDictionary(new ClientIdAndCredentials
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                });
            }
            request.Content = new FormUrlEncodedContent(nameValueCollection);

#if NET || NETCORE
            var httpClient = httpClientFactory.CreateClient();
#endif

            using (var response = await httpClient.SendAsync(request))
            {
                try
                {
                    var result = await response.Content.ReadAsStringAsync();

                    var tokenResponse = result.ToObject<Tres>();
                    if (tokenResponse is TokenResponse vtr)
                    {
                        vtr.Validate();
                    }
                    else if (tokenResponse is TokenExchangeResponse vter)
                    {
                        vter.Validate();
                    }
                    else
                    {
                        throw new NotSupportedException($"Token response type '{tokenResponse.GetType()}' not supported.");
                    }
                    return tokenResponse;
                }
                catch (Exception ex)
                {
                    throw new ResponseException($"Error getting access token with client credentials. StatusCode={response.StatusCode}", ex);
                }
            }
        }

        /// <summary>
        /// Execute token request with assertion in client credential grant.
        /// </summary>
        /// <typeparam name="Treq">Of the type TokenBaseRequest.</typeparam>
        /// <typeparam name="Tres">Of the type TokenBaseResponse.</typeparam>
        /// <param name="jsonWebClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="tokenEndpoint">The token endpoint.</param>
        /// <param name="tokenRequest">The token request.</param>
        /// <param name="clientAssertionExpiresIn">The client assertion expires in.</param>
        /// <returns>The <typeparam>Tres</typeparam> token response.</returns>
        public Task<Tres> ExecuteTokenRequestWithAssertionClientCredentialGrantAsync<Treq, Tres>(JsonWebKey jsonWebClientKey, string clientId, string tokenEndpoint, Treq tokenRequest = null, int clientAssertionExpiresIn = 30) where Treq : TokenBaseRequest, new() where Tres : TokenBaseResponse
        {
            return ExecuteTokenRequestWithAssertionClientCredentialGrantAsync<Treq, Tres>(jsonWebClientKey.ToSecurityKey(), clientId, tokenEndpoint, tokenRequest: tokenRequest, clientAssertionExpiresIn: clientAssertionExpiresIn);
        }

        /// <summary>
        /// Execute token request with assertion in client credential grant.
        /// </summary>
        /// <typeparam name="Treq">Of the type TokenBaseRequest.</typeparam>
        /// <typeparam name="Tres">Of the type TokenBaseResponse.</typeparam>
        /// <param name="certificateClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="tokenEndpoint">The token endpoint.</param>
        /// <param name="tokenRequest">The token request.</param>
        /// <param name="clientAssertionExpiresIn">The client assertion expires in.</param>
        /// <returns>The <typeparam>Tres</typeparam> token response.</returns>
        public Task<Tres> ExecuteTokenRequestWithAssertionClientCredentialGrantAsync<Treq, Tres>(X509Certificate2 certificateClientKey, string clientId, string tokenEndpoint, Treq tokenRequest = null, int clientAssertionExpiresIn = 30) where Treq : TokenBaseRequest, new() where Tres : TokenBaseResponse
        {
            return ExecuteTokenRequestWithAssertionClientCredentialGrantAsync<Treq, Tres>(new MSTokens.X509SecurityKey(certificateClientKey), clientId, tokenEndpoint, tokenRequest: tokenRequest, clientAssertionExpiresIn: clientAssertionExpiresIn);
        }

        /// <summary>
        /// Execute token request with assertion in client credential grant.
        /// </summary>
        /// <typeparam name="Treq">Of the type TokenBaseRequest.</typeparam>
        /// <typeparam name="Tres">Of the type TokenBaseResponse.</typeparam>
        /// <param name="securityClientKey">The client key (certificate).</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="tokenEndpoint">The token endpoint.</param>
        /// <param name="tokenRequest">The token request.</param>
        /// <param name="clientAssertionExpiresIn">The client assertion expires in.</param>
        /// <returns>The <typeparam>Tres</typeparam> token response.</returns>
        public async Task<Tres> ExecuteTokenRequestWithAssertionClientCredentialGrantAsync<Treq, Tres>(MSTokens.SecurityKey securityClientKey, string clientId, string tokenEndpoint, Treq tokenRequest = null, int clientAssertionExpiresIn = 30) where Treq : TokenBaseRequest, new() where Tres : TokenBaseResponse
        {
            if (securityClientKey == null) throw new ArgumentNullException(nameof(securityClientKey));
            if (clientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientId));
            if (tokenEndpoint.IsNullOrEmpty()) throw new ArgumentNullException(nameof(tokenEndpoint));
            
            if (tokenRequest == null)
            {
                tokenRequest = new Treq();
            }

            if (tokenRequest is TokenRequest tr)
            {
                tr.ClientId = clientId;
            }

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
            var nameValueCollection = tokenRequest.ToDictionary().AddToDictionary(clientAssertionCredentials);
            request.Content = new FormUrlEncodedContent(nameValueCollection);

#if NET || NETCORE
            var httpClient = httpClientFactory.CreateClient();
#endif

            using (var response = await httpClient.SendAsync(request))
            {
                try
                {
                    var result = await response.Content.ReadAsStringAsync();

                    var tokenResponse = result.ToObject<Tres>();
                    if (tokenResponse is TokenResponse vtr)
                    {
                        vtr.Validate();
                    }
                    else if (tokenResponse is TokenExchangeResponse vter)
                    {
                        vter.Validate();
                    }
                    else
                    {
                        throw new NotSupportedException($"Token response type '{tokenResponse.GetType()}' not supported.");
                    }
                    return tokenResponse;
                }
                catch (Exception ex)
                {
                    throw new ResponseException($"Error execute token request with client credentials. StatusCode={response.StatusCode}", ex);
                }
            }
        }
    }
}
