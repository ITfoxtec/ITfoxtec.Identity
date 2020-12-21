using ITfoxtec.Identity.Models;
using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Discovery
{
    /// <summary>
    /// Call OIDC Discovery and cache result designed to be handled by a BackgroundService.
    /// </summary>
    public class OidcDiscoveryHandlerService : OidcDiscoveryHandlerBase
    {
#if NET || NETCORE
        private readonly IHttpClientFactory httpClientFactory;
#else
        private readonly HttpClient httpClient;
#endif
        private readonly string defaultOidcDiscoveryUri;
        private readonly int defaultExpiresIn;
        private ConcurrentDictionary<string, (OidcDiscovery, DateTimeOffset)> oidcDiscoveryCache = new ConcurrentDictionary<string, (OidcDiscovery, DateTimeOffset)>();
        private ConcurrentDictionary<string, (JsonWebKeySet, DateTimeOffset)> jsonWebKeySetCache = new ConcurrentDictionary<string, (JsonWebKeySet, DateTimeOffset)>();

        /// <summary>
        /// Call OIDC Discovery and cache result.
        /// </summary>
        /// <param name="defaultOidcDiscoveryUri">The default OIDC Discovery Uri.</param>
        /// <param name="defaultExpiresIn">The default expires in seconds.</param>
        public OidcDiscoveryHandlerService(
#if NET || NETCORE
            IHttpClientFactory httpClientFactory,
#else
            HttpClient httpClient,
#endif
            string defaultOidcDiscoveryUri = null, int defaultExpiresIn = 3600) : base
            (
#if NET || NETCORE
            httpClientFactory,
#else
            httpClient,
#endif
               defaultOidcDiscoveryUri, defaultExpiresIn)
        {
#if NET || NETCORE
            this.httpClientFactory = httpClientFactory;
#else
            this.httpClient = httpClient;
#endif
            this.defaultOidcDiscoveryUri = defaultOidcDiscoveryUri;
            this.defaultExpiresIn = defaultExpiresIn;
        }

        /// <summary>
        /// Should be used to clean old cache items.
        /// </summary>
        /// <param name="stoppingToken">CancellationToken triggered to stop.</param>
        /// <returns>Returns long running task that cleans old cache items.</returns>
        public async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await CleanOldCacheItemsAsync(stoppingToken);
        }
    }
}
