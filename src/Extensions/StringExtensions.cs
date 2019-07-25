using Microsoft.AspNetCore.WebUtilities;
using System;
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
        /// Base64 url encode a string.
        /// </summary>
        public static string Base64UrlEncode(this string value)
        {
            if (value == null) new ArgumentNullException(nameof(value));

            return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        /// Base64 url decode a string.
        /// </summary>
        public static string Base64UrlDecode(this string value)
        {
            if (value == null) new ArgumentNullException(nameof(value));

            return Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(value));
        }

        /// <summary>
        /// Base64 encode a string.
        /// </summary>
        public static string Base64Encode(this string value)
        {
            if (value == null) new ArgumentNullException(nameof(value));

            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        /// Base64 decode a string.
        /// </summary>
        public static string Base64Decode(this string value)
        {
            if (value == null) new ArgumentNullException(nameof(value));

            return Encoding.UTF8.GetString(Convert.FromBase64String(value));
        }

        /// <summary>
        /// Compute a base64url encoded left-most half of the hash of the octets of the ASCII representation of a value. 
        /// For instance, if the algorithm is RS256, hash the value with SHA-256, then take the left-most 128 bits and base64url encode them.
        /// </summary>
        public static Task<string> LeftMostBase64urlEncodingHash(this string value, string algorithm)
        {
            if (value == null) new ArgumentNullException(nameof(value));
            if (algorithm != IdentityConstants.Algorithms.Asymmetric.RS256) throw new NotSupportedException($"Algorithm {algorithm} not supported. Supports {IdentityConstants.Algorithms.Asymmetric.RS256}.");

            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(value));
                return Task.FromResult(WebEncoders.Base64UrlEncode(hash.Take(16).ToArray()));
            }
        }
    }
}
