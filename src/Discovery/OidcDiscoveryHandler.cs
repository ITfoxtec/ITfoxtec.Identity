﻿using ITfoxtec.Identity.Models;
using System;
using System.Collections.Concurrent;
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
        public OidcDiscoveryHandler(
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
