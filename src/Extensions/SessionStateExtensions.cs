using ITfoxtec.Identity.Util;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.Extensions
{
    /// <summary>
    /// Session state extensions.
    /// </summary>
    public static class SessionStateExtensions
    {
        /// <summary>
        /// Calculate session state value.
        /// </summary>
        public static string GetSessionStateValue(this string sessionId, string clientId, string redirectUri)
        {
            if (sessionId.IsNullOrEmpty()  || clientId.IsNullOrWhiteSpace() || redirectUri.IsNullOrWhiteSpace())
            {
                return null;
            }

            var salt = RandomGenerator.GenerateBytes(16);
            return $"{$"{clientId} {redirectUri.UrlToOrigin()} {sessionId} {salt}".Sha256HashBase64urlEncoded()}.{salt}";
        }

        /// <summary>
        /// Calculate session state value.
        /// </summary>
        public static Task<string> GetSessionStateValueAsync(this string sessionId, string clientId, string redirectUri)
        {
            return Task.FromResult(sessionId.GetSessionStateValue(clientId, redirectUri));
        }
    }
}
