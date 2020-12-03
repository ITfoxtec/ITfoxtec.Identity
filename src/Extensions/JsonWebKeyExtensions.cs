using System;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using Microsoft.IdentityModel.Tokens;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for JsonWebKey.
    /// </summary>
    public static class JsonWebKeyExtensions
    {
        /// <summary>
        /// Get public JWK.
        /// </summary>
        public static JsonWebKey GetPublicKey(this JsonWebKey jwk)
        {
            var publicKey = new JsonWebKey
            {
                Kty = jwk.Kty,
                Kid = jwk.Kid,
                X5t = jwk.X5t,
                N = jwk.N,
                E = jwk.E
            };
            if (jwk.X5c != null && jwk.X5c.Count() > 0)
            {
                publicKey.X5c.Add(jwk.X5c.First());
            }
            return publicKey;
        }

        /// <summary>
        /// Converts a JWK to RSA parameters.
        /// </summary>
        public static RSAParameters ToRsaParameters(this JsonWebKey jwk, bool includePrivateParameters = false)
        {
            if (jwk == null) new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Only key type '{JsonWebAlgorithmsKeyTypes.RSA }' supported.");

            if (jwk.N.IsNullOrEmpty()) new ArgumentNullException(nameof(jwk.N), jwk.GetTypeName());
            if (jwk.E.IsNullOrEmpty()) new ArgumentNullException(nameof(jwk.E), jwk.GetTypeName());

            var rsaParameters = new RSAParameters();
            rsaParameters.Modulus = WebEncoders.Base64UrlDecode(jwk.N);
            rsaParameters.Exponent = WebEncoders.Base64UrlDecode(jwk.E);

            if (includePrivateParameters && !jwk.D.IsNullOrEmpty() && !jwk.P.IsNullOrEmpty() && !jwk.Q.IsNullOrEmpty() && !jwk.DP.IsNullOrEmpty() && !jwk.DQ.IsNullOrEmpty() && !jwk.QI.IsNullOrEmpty())
            {
                rsaParameters.D = WebEncoders.Base64UrlDecode(jwk.D);
                rsaParameters.P = WebEncoders.Base64UrlDecode(jwk.P);
                rsaParameters.Q = WebEncoders.Base64UrlDecode(jwk.Q);
                rsaParameters.DP = WebEncoders.Base64UrlDecode(jwk.DP);
                rsaParameters.DQ = WebEncoders.Base64UrlDecode(jwk.DQ);
                rsaParameters.InverseQ = WebEncoders.Base64UrlDecode(jwk.QI);
            }

            return rsaParameters;
        }

#if NET || NETCORE
        /// <summary>
        /// Converts a JWK to RSA.
        /// </summary>
        public static RSA ToRsa(this JsonWebKey jwk, bool includePrivateParameters = false)
        {
            return RSA.Create(jwk.ToRsaParameters(includePrivateParameters));
        }
#endif

        /// <summary>
        /// Converts a JWK to public X509Certificate.
        /// </summary>
        public static X509Certificate2 ToX509Certificate(this JsonWebKey jwk)
        {
            if (jwk == null) new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Key type '{jwk.Kty}' not supported. Only key type '{JsonWebAlgorithmsKeyTypes.RSA }' supported.");

            if (jwk.X5c == null || jwk.X5c.Count() <= 0) throw new ArgumentNullException(nameof(jwk.X5c), jwk.GetTypeName());

            var certificate = new X509Certificate2(Convert.FromBase64String(jwk.X5c.First()));
            if (!jwk.X5t.IsNullOrEmpty())
            {
                if (jwk.X5t != WebEncoders.Base64UrlEncode(certificate.GetCertHash()))
                {
                    throw new Exception("X.509 certificate SHA-1 thumbprint do not match certificate.");
                }
            }

            return certificate;
        }
    }
}
