using ITfoxtec.Identity.Util;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for strings.
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        /// Indicates whether the specified string is null or an System.String.Empty string.
        /// </summary>
        public static bool IsNullOrEmpty(this string value)
        {
            return string.IsNullOrEmpty(value);
        }

        /// <summary>
        /// Indicates whether a specified string is null, empty, or consists only of white-space characters.
        /// </summary>
        public static bool IsNullOrWhiteSpace(this string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        /// <summary>
        /// Validate a specified list min length.
        /// </summary>
        public static void ValidateMinListLength(this IEnumerable<string> list, int minCount, string paramName, string className)
        {
            if (list == null || list.Count() < minCount)
            {
                throw new ArgumentException($"Invalid list, min length {minCount}.", $"{paramName} at {className}");
            }
        }

        /// <summary>
        /// Validate a specified list max length.
        /// </summary>
        public static void ValidateMaxListLength(this IEnumerable<string> list, int maxCount, string paramName, string className)
        {
            if (list?.Count() > maxCount)
            {
                throw new ArgumentException($"Invalid list, max length {maxCount}.", $"{paramName} at {className}");
            }
        }

        /// <summary>
        /// Validate a specified string min length.
        /// </summary>
        public static void ValidateMinLength(this string value, int minLength, string paramName, string className)
        {
            if (!string.IsNullOrEmpty(value) && value.Length < minLength)
            {
                throw new ArgumentException($"Invalid value, min length {minLength}.", $"{paramName} at {className}");
            }
        }

        /// <summary>
        /// Validate a specified string max length.
        /// </summary>
        public static void ValidateMaxLength(this string value, int maxLength, string paramName, string className)
        {
            if(!string.IsNullOrEmpty(value) && value.Length > maxLength)
            {
                throw new ArgumentException($"Invalid value, max length {maxLength}.", $"{paramName} at {className}");
            }
        }

        /// <summary>
        /// Convert URL to domain.
        /// </summary>
        public static string UrlToDomain(this string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return null;
            }

            var splitValue = url.Split('/');
            if (splitValue.Count() > 2)
            {
                var domain = splitValue[2].ToLower();
                return domain;
            }
            return null;
        }

        /// <summary>
        /// Convert domain to origin.
        /// </summary>
        public static string DomainToOrigin(this string domain, bool scheme)
        {
            if (string.IsNullOrEmpty(domain))
            {
                return null;
            }

            return $"{scheme}://{domain}";
        }

        /// <summary>
        /// Convert URL to origin.
        /// </summary>
        public static string UrlToOrigin(this string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return null;
            }

            string[] splitScema = url.ToLower().Split("://");
            if (splitScema.Count() > 1)
            {
                string[] splitDomain = splitScema[1].Split('/');
                if (splitDomain.Count() >= 1)
                {
                    return $"{splitScema[0]}://{splitDomain[0]}";

                }
            }

            return null;
        }

        /// <summary>
        /// Base64 URL encode a string.
        /// </summary>
        public static string Base64UrlEncode(this string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        /// Base64 URL decode a string.
        /// </summary>
        public static string Base64UrlDecode(this string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            return Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(value));
        }

        /// <summary>
        /// Base64 encode a string.
        /// </summary>
        public static string Base64Encode(this string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        /// Base64 decode a string.
        /// </summary>
        public static string Base64Decode(this string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            return Encoding.UTF8.GetString(Convert.FromBase64String(value));
        }

        /// <summary>
        /// Base64 URL encoded SHA-256 hash. Code challenge method S256.
        /// </summary>
        public static string Sha256HashBase64urlEncoded(this string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
        
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(value));
                return WebEncoders.Base64UrlEncode(hash);
            }
        }

        /// <summary>
        /// Base64 URL encoded SHA-256 hash. Code challenge method S256.
        /// </summary>
        public static Task<string> Sha256HashBase64urlEncodedAsync(this string value)
        {
            return Task.FromResult(value.Sha256HashBase64urlEncoded());
        }

        /// <summary>
        /// Compute a base64url encoded left-most half of the hash of the octets of the ASCII representation of a value. 
        /// For instance, if the algorithm is RS256, hash the value with SHA-256, then take the left-most 128 bits and base64url encode them.
        /// </summary>
        public static string LeftMostBase64urlEncodedHash(this string value, string algorithm)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            if (algorithm != IdentityConstants.Algorithms.Asymmetric.RS256) throw new NotSupportedException($"Algorithm {algorithm} not supported. Supports {IdentityConstants.Algorithms.Asymmetric.RS256}.");

            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(value));
                return WebEncoders.Base64UrlEncode(hash.Take(16).ToArray());
            }
        }

        /// <summary>
        /// Compute a base64url encoded left-most half of the hash of the octets of the ASCII representation of a value. 
        /// For instance, if the algorithm is RS256, hash the value with SHA-256, then take the left-most 128 bits and base64url encode them.
        /// </summary>
        public static Task<string> LeftMostBase64urlEncodedHashAsync(this string value, string algorithm)
        {
            return Task.FromResult(value.LeftMostBase64urlEncodedHash(algorithm));
        }

        /// <summary>
        /// Combines the URL base and the relative URL into one, consolidating the '/' between them
        /// </summary>
        /// <param name="baseUrl">Base URL that will be combined</param>
        /// <param name="relativeUrl">The relative path to combine</param>
        /// <returns>The merged URL</returns>
        public static string CombineUrl(this string baseUrl, string relativeUrl) => UrlCombine.Combine(baseUrl, relativeUrl);

        /// <summary>
        /// Combines the URL base and the array of relative URLs into one, consolidating the '/' between them
        /// </summary>
        /// <param name="baseUrl">Base URL that will be combined</param>
        /// <param name="relativeUrls">The array of relative paths to combine</param>
        /// <returns>The merged URL</returns>
        public static string CombineUrl(this string baseUrl, params string[] relativeUrls) => UrlCombine.Combine(baseUrl, relativeUrls);
    }
}
