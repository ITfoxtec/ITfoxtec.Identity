using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Discovery
{
    public class OidcDiscoveryHandler
    {
        private readonly string oidcDiscoveryUri;
        private readonly int expiresIn;
        private OidcDiscovery oidcDiscovery;
        private JsonWebKeySet jsonWebKeySet;
        private DateTimeOffset oidcDiscoveryValidUntil = DateTimeOffset.MinValue;
        private DateTimeOffset jsonWebKeySetValidUntil = DateTimeOffset.MinValue;

        public OidcDiscoveryHandler(string oidcDiscoveryUri, int expiresIn = 3600)
        {
            this.oidcDiscoveryUri = oidcDiscoveryUri;
            this.expiresIn = expiresIn;
        }

        public async Task<OidcDiscovery> GetOidcDiscovery()
        {
            if (oidcDiscovery == null || oidcDiscoveryValidUntil < DateTimeOffset.UtcNow)
            {
                using (var client = new HttpClient())
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, oidcDiscoveryUri);

                    using (var response = await client.SendAsync(request))
                    {
                        // Handle the response
                        switch (response.StatusCode)
                        {
                            case HttpStatusCode.OK:
                                var result = await response.Content.ReadAsStringAsync();
                                oidcDiscovery = result.ToObject<OidcDiscovery>();
                                oidcDiscoveryValidUntil = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
                                break;

                            default:
                                throw new Exception($"Error, Status Code OK expected. StatusCode={response.StatusCode}");
                        }
                    }

                }
            }

            return oidcDiscovery;
        }

        public async Task<JsonWebKeySet> GetOidcDiscoveryKeys()
        {
            if (jsonWebKeySet == null || jsonWebKeySetValidUntil < DateTimeOffset.UtcNow)
            {
                await GetOidcDiscovery();
                using (var client = new HttpClient())
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, oidcDiscovery.JwksUri);

                    using (var response = await client.SendAsync(request))
                    {
                        // Handle the response
                        switch (response.StatusCode)
                        {
                            case HttpStatusCode.OK:
                                var result = await response.Content.ReadAsStringAsync();
                                jsonWebKeySet = result.ToObject<JsonWebKeySet>();
                                jsonWebKeySetValidUntil = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
                                break;

                            default:
                                throw new Exception($"Error, Status Code OK expected. StatusCode={response.StatusCode}");
                        }
                    }

                }
            }

            return jsonWebKeySet;
        }
    }
}
