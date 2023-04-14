using System;
using System.Linq;

namespace ITfoxtec.Identity.Util
{
    public static class UrlCombine
    {
        /// <summary>
        /// Combines the URL base and the relative URL into one, consolidating the '/' between them
        /// </summary>
        /// <param name="baseUrl">Base URL that will be combined</param>
        /// <param name="relativeUrl">The relative path to combine</param>
        /// <returns>The merged URL</returns>
        public static string Combine(string baseUrl, string relativeUrl)
        {
            if (baseUrl.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(baseUrl));

            if (relativeUrl.IsNullOrWhiteSpace())
                return baseUrl;

            baseUrl = baseUrl.TrimEnd('/');
            relativeUrl = relativeUrl.TrimStart('/');

            return $"{baseUrl}/{relativeUrl}";
        }

        /// <summary>
        /// Combines the URL base and the array of relatives URLs into one, consolidating the '/' between them
        /// </summary>
        /// <param name="baseUrl">Base URL that will be combined</param>
        /// <param name="relativePaths">The array of relative paths to combine</param>
        /// <returns>The merged URL</returns>
        public static string Combine(string baseUrl, params string[] relativePaths)
        {
            if (baseUrl.IsNullOrWhiteSpace())
                throw new ArgumentNullException(nameof(baseUrl));

            if (relativePaths.Length == 0)
                return baseUrl;

            var currentUrl = Combine(baseUrl, relativePaths[0]);

            return Combine(currentUrl, relativePaths.Skip(1).ToArray());
        }
    }
}
