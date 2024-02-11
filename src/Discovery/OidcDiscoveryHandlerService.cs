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
        /// <summary>
        /// Call OIDC Discovery and cache result.
        /// </summary>
        /// <param name="defaultOidcDiscoveryUri">The default OIDC Discovery Uri.</param>
        /// <param name="defaultExpiresIn">The default expires in seconds.</param>
        public OidcDiscoveryHandlerService(IHttpClientFactory httpClientFactory, string defaultOidcDiscoveryUri = null, int defaultExpiresIn = 3600) : base(httpClientFactory, defaultOidcDiscoveryUri, defaultExpiresIn)
        { }

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
