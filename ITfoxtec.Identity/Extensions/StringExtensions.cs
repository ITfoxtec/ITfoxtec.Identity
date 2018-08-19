using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Text;

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
    }
}
