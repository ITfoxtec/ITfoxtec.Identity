using ITfoxtec.Identity.Discovery;
using ITfoxtec.Identity.Tokens;
using System;
using System.Linq;
using System.Net.Http;
using System.Security;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Helpers
{
    public class OidcHelper
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
        public OidcHelper(
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


        public async Task<ClaimsPrincipal> ValidateOidcWithUserInfoEndpoint(string idToken, string accessToken, string nonce = null)
        {
            if (idToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(idToken));
            if (accessToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(accessToken));

            var idTokenPrincipal = JwtHandler.ReadTokenClaims(idToken);

            var idTokenAtHash = idTokenPrincipal.Claims.Where(c => c.Type == JwtClaimTypes.AtHash).Select(c => c.Value).FirstOrDefault();
            string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256;
            if (idTokenAtHash != await accessToken.LeftMostBase64urlEncodedHashAsync(algorithm))
            {
                throw new SecurityException("Access Token hash claim in ID token do not match the access token.");
            }

            if (!nonce.IsNullOrEmpty())
            {
                var idTokenNonce = idTokenPrincipal.Claims.Where(c => c.Type == JwtClaimTypes.Nonce).Select(c => c.Value).FirstOrDefault();
                if (!nonce.Equals(idTokenNonce, StringComparison.Ordinal))
                {
                    throw new SecurityException("Nonce claim in ID token do not match the nonce value.");
                }
            }

            await ValidateAccessTokenWithUserInfoEndpoint(accessToken);

            return idTokenPrincipal;
        }

        public async Task ValidateAccessTokenWithUserInfoEndpoint(string accessToken)
        {
            var userInfoEndpoint = (await oidcDiscoveryHandler.GetOidcDiscoveryAsync()).UserInfoEndpoint;

            var client = httpClientFactory.CreateClient();
            client.SetAuthorizationHeaderBearer(accessToken);
            using var response = await client.GetAsync(userInfoEndpoint);
            if (response.IsSuccessStatusCode)
            {
                return;
            }
            else
            {
                var wwwAuthenticateError = string.Empty;
                if (response.Headers?.WwwAuthenticate?.Count() > 0)
                {
                    wwwAuthenticateError = $", WWWAuthenticateError '{string.Join(", ", response.Headers.WwwAuthenticate)}'";
                }

                throw new SecurityException($"User Info endpoint error. URL '{userInfoEndpoint}', StatusCode '{response.StatusCode}'{wwwAuthenticateError}.");
            }
        } 

    }
}
