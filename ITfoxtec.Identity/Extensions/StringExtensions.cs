using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for strings.
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        /// Base64 url encode a string.
        /// </summary>
        public static string Base64UrlEncode(this string value)
        {
            return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(value));
        }

        /// <summary>
        /// Base64 url decode a string.
        /// </summary>
        public static string Base64UrlDecode(this string value)
        {
            return Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(value));
        }
    }
}
