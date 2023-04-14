using ITfoxtec.Identity.Util;
using System;

namespace ITfoxtec.Identity
{
    public static class UriExtension
    {
        /// <summary>
        /// Combines the URI with a base path and the relative URL into one, consolidating the '/' between them
        /// </summary>
        /// <param name="baseUri">Base URI that will be combined</param>
        /// <param name="relativeUrl">The relative path to combine</param>
        /// <returns>The merged URI</returns>
        public static Uri Combine(this Uri baseUri, string relativeUrl)
        {
            if (baseUri == null)
                throw new ArgumentNullException(nameof(baseUri));

            return new Uri(UrlCombine.Combine(baseUri.OriginalString, relativeUrl));
        }

        /// <summary>
        /// Combines the URI with base path and the array of relative URLs into one, consolidating the '/' between them
        /// </summary>
        /// <param name="baseUri">Base URI that will be combined</param>
        /// <param name="relativePaths">The array of relative paths to combine</param>
        /// <returns>The merged URI</returns>
        public static Uri Combine(this Uri baseUri, params string[] relativePaths)
        {
            if (baseUri == null)
                throw new ArgumentNullException(nameof(baseUri));

            return new Uri(UrlCombine.Combine(baseUri.OriginalString, relativePaths));
        }
    }
}
