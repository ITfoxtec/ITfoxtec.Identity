using ITfoxtec.Identity.Discovery;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for JWK.
    /// </summary>
    public static class JwkExtensions
    {
        /// <summary>
        /// Converts a JWK to X509 Certificate.
        /// </summary>
        public static Task<X509Certificate2> ToJwtString(this JsonWebKey jwk)
        {
            throw new NotImplementedException();
        }
    }
}
