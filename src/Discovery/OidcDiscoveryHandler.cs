using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Discovery
{
    /// <summary>
    /// Call OIDC Discovery and cache result.
    /// </summary>
    public class OidcDiscoveryHandler : OidcDiscoveryHandlerBase, IDisposable
    {
        private readonly CancellationTokenSource cleanUpCancellationTokenSource;

        /// <summary>
        /// Call OIDC Discovery and cache result.
        /// </summary>
        /// <param name="defaultOidcDiscoveryUri">The default OIDC Discovery Uri.</param>
        /// <param name="defaultExpiresIn">The default expires in seconds.</param>
        public OidcDiscoveryHandler(IHttpClientFactory httpClientFactory, string defaultOidcDiscoveryUri = null, int defaultExpiresIn = 3600) : base(httpClientFactory, defaultOidcDiscoveryUri, defaultExpiresIn)
        {
            cleanUpCancellationTokenSource = new CancellationTokenSource();
            Task.Factory.StartNew(async () => { await CleanOldCacheItemsAsync(cleanUpCancellationTokenSource.Token); }, cleanUpCancellationTokenSource.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        bool isDisposed = false;
        public void Dispose()
        {
            if (!isDisposed)
            {
                isDisposed = true;
                cleanUpCancellationTokenSource.Cancel();
            }
        }
    }
}
