using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for RSA.
    /// </summary>
    public static class RsaExtensions
    {
        /// <summary>
        /// Converts a RSA to a SecurityKey.
        /// </summary>
        public static SecurityKey ToSecurityKey(this RSA rsa, string kid)
        {
            var key = new RsaSecurityKey(rsa);
            key.KeyId = kid;
            return key;
        }
    }
}
