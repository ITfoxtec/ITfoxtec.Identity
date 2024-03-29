﻿using ITfoxtec.Identity.Models;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Discovery
{
    /// <summary>
    /// Base class for calling OIDC Discovery and cache result.
    /// </summary>
    public abstract class OidcDiscoveryHandlerBase
    {
        private readonly IHttpClientFactory httpClientFactory;
        private string defaultOidcDiscoveryUri;
        private readonly int defaultExpiresIn;
        private ConcurrentDictionary<string, (OidcDiscovery, DateTimeOffset)> oidcDiscoveryCache = new ConcurrentDictionary<string, (OidcDiscovery, DateTimeOffset)>();
        private ConcurrentDictionary<string, (JsonWebKeySet, DateTimeOffset)> jsonWebKeySetCache = new ConcurrentDictionary<string, (JsonWebKeySet, DateTimeOffset)>();

        /// <summary>
        /// Call OIDC Discovery and cache result.
        /// </summary>
        /// <param name="defaultOidcDiscoveryUri">The default OIDC Discovery Uri.</param>
        /// <param name="defaultExpiresIn">The default expires in seconds.</param>
        public OidcDiscoveryHandlerBase(IHttpClientFactory httpClientFactory, string defaultOidcDiscoveryUri = null, int defaultExpiresIn = 3600)
        {
            this.httpClientFactory = httpClientFactory;
            this.defaultOidcDiscoveryUri = defaultOidcDiscoveryUri;
            this.defaultExpiresIn = defaultExpiresIn;
        }

        protected async Task CleanOldCacheItemsAsync(CancellationToken stoppingToken)
        {
            while (true)
            {
                try
                {
                    stoppingToken.ThrowIfCancellationRequested();
                    await Task.Delay(new TimeSpan(2, 0, 0), stoppingToken);

                    stoppingToken.ThrowIfCancellationRequested();
                    var olderThenUtcNow = DateTimeOffset.UtcNow.AddHours(-4);
                    foreach (var item in oidcDiscoveryCache)
                    {
                        (_, var oidcDiscoveryValidUntil) = item.Value;
                        if (oidcDiscoveryValidUntil < olderThenUtcNow)
                        {
                            if (!oidcDiscoveryCache.TryRemove(item.Key, out _))
                            {
                                Debug.WriteLine($"OidcDiscoveryHandler unable to remove key '{item.Key}' from oidcDiscoveryCache.");
                            }
                        }
                    }

                    stoppingToken.ThrowIfCancellationRequested();
                    foreach (var item in jsonWebKeySetCache)
                    {
                        (_, var jsonWebKeySetValidUntil) = item.Value;
                        if (jsonWebKeySetValidUntil < olderThenUtcNow)
                        {
                            if (!jsonWebKeySetCache.TryRemove(item.Key, out _))
                            {
                                Debug.WriteLine($"OidcDiscoveryHandler unable to remove key '{item.Key}' from jsonWebKeySetCache.");
                            }
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (ObjectDisposedException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"OidcDiscoveryHandler clean failed. {ex}");
                }
            }
        }

        /// <summary>
        /// Set the default OIDC Discovery Uri.
        /// </summary>
        /// <param name="oidcDiscoveryUri">The OIDC Discovery Uri.</param>
        public void SetDefaultOidcDiscoveryUri(string oidcDiscoveryUri)
        {
            defaultOidcDiscoveryUri = oidcDiscoveryUri;
        }

        /// <summary>
        /// Call OIDC Discovery endpoint or read the OIDC Discovery from the cache.
        /// </summary>
        /// <param name="oidcDiscoveryUri">The OIDC Discovery Uri. If not specified the default OIDC Discovery Uri is used.</param>
        /// <param name="expiresIn">The expires in seconds. If not specified the default expires in is used.</param>
        /// <param name="refreshCache">Reload and refresh cache.</param>
        /// <returns>Return OIDC Discovery result.</returns>
        public async Task<OidcDiscovery> GetOidcDiscoveryAsync(string oidcDiscoveryUri = null, int? expiresIn = null, bool refreshCache = false)
        {
            oidcDiscoveryUri = oidcDiscoveryUri ?? defaultOidcDiscoveryUri;
            expiresIn = expiresIn ?? defaultExpiresIn;

            if (!refreshCache && oidcDiscoveryCache.ContainsKey(oidcDiscoveryUri))
            {
                (var oidcDiscovery, var oidcDiscoveryValidUntil) = oidcDiscoveryCache[oidcDiscoveryUri];
                if (oidcDiscoveryValidUntil >= DateTimeOffset.UtcNow)
                {
                    return oidcDiscovery;
                }
            }

            var request = new HttpRequestMessage(HttpMethod.Get, oidcDiscoveryUri);
            using (var response = await httpClientFactory.CreateClient().SendAsync(request))
            {
                // Handle the response
                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                        var result = await response.Content.ReadAsStringAsync();
                        var oidcDiscovery = result.ToObject<OidcDiscovery>();
                        var oidcDiscoveryValidUntil = DateTimeOffset.UtcNow.AddSeconds(expiresIn.Value);

                        try
                        {
                            oidcDiscoveryCache[oidcDiscoveryUri] = (oidcDiscovery, oidcDiscoveryValidUntil);
                        }
                        catch
                        { }

                        return oidcDiscovery;

                    default:
                        throw new Exception($"Error, Status Code OK expected. StatusCode={response.StatusCode}. Invalid or unable do call OidcDiscoveryUri='{oidcDiscoveryUri}'.");
                }
            }
        }

        /// <summary>
        /// Call OIDC Discovery Keys endpoint or read the OIDC Discovery Keys from the cache.
        /// </summary>
        /// <param name="oidcDiscoveryUri">The OIDC Discovery Uri, used to resolve the Keys endpoint. If not specified the default OIDC Discovery Uri is used.</param>
        /// <param name="expiresIn">The expires in seconds. If not specified the default expires in is used.</param>
        /// <param name="refreshCache">Reload and refresh cache.</param>
        /// <returns>Return OIDC Discovery Keys result.</returns>
        public async Task<JsonWebKeySet> GetOidcDiscoveryKeysAsync(string oidcDiscoveryUri = null, int? expiresIn = null, bool refreshCache = false)
        {
            oidcDiscoveryUri = oidcDiscoveryUri ?? defaultOidcDiscoveryUri;
            expiresIn = expiresIn ?? defaultExpiresIn;

            if (!refreshCache && jsonWebKeySetCache.ContainsKey(oidcDiscoveryUri))
            {
                (var jsonWebKeySet, var jsonWebKeySetValidUntil) = jsonWebKeySetCache[oidcDiscoveryUri];
                if (jsonWebKeySetValidUntil >= DateTimeOffset.UtcNow)
                {
                    return jsonWebKeySet;
                }
            }

            var oidcDiscovery = await GetOidcDiscoveryAsync(oidcDiscoveryUri, expiresIn);
            var request = new HttpRequestMessage(HttpMethod.Get, oidcDiscovery.JwksUri);
            using (var response = await httpClientFactory.CreateClient().SendAsync(request))
            {
                // Handle the response
                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                        var result = await response.Content.ReadAsStringAsync();
                        var jsonWebKeySet = result.ToObject<JsonWebKeySet>();
                        var jsonWebKeySetValidUntil = DateTimeOffset.UtcNow.AddSeconds(expiresIn.Value);

                        try
                        {
                            jsonWebKeySetCache[oidcDiscoveryUri] = (jsonWebKeySet, jsonWebKeySetValidUntil);
                        }
                        catch
                        { }

                        return jsonWebKeySet;

                    default:
                        throw new Exception($"Error, Status Code OK expected. StatusCode={response.StatusCode}. Invalid or unable do call OidcDiscoveryJwksUri='{oidcDiscovery.JwksUri}'.");
                }
            }
        }
    }
}
