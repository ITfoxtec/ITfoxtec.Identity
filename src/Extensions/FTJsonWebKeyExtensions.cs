using System;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using MSTokens = Microsoft.IdentityModel.Tokens;
using ITfoxtec.Identity.Models;
using System.Collections.Generic;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for ITfoxtec JsonWebKey.
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
                X5t = jwk.X5t,
                Kid = jwk.Kid,
                N = jwk.N,
                E = jwk.E
            };
            if (jwk.X5c?.Count() > 0)
            {
                publicKey.X5c = new List<string> { jwk.X5c.First() };
            }
            return publicKey;
        }

        /// <summary>
        /// Converts a JWK to RSA parameters.
        /// </summary>
        public static RSAParameters ToRsaParameters(this JsonWebKey jwk, bool includePrivateParameters = false)
        {
            if (jwk == null) throw new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != MSTokens.JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Only key type '{MSTokens.JsonWebAlgorithmsKeyTypes.RSA }' supported.");

            if (jwk.N.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.N), jwk.GetTypeName());
            if (jwk.E.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.E), jwk.GetTypeName());

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

        /// <summary>
        /// Converts a ITfoxtec JWK to a SecurityKey.
        /// </summary>
        public static MSTokens.SecurityKey ToSecurityKey(this JsonWebKey jwk)
        {
            var key = new MSTokens.RsaSecurityKey(jwk.ToRsaParameters(true));
            key.KeyId = jwk.Kid;
            return key;
        }

        /// <summary>
        /// Converts a ITfoxtec JWK to a Microsoft JWK.
        /// </summary>
        public static MSTokens.JsonWebKey ToMSJsonWebKey(this JsonWebKey jwk, bool includePrivateKey = false)
        {
            if (jwk == null) throw new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != MSTokens.JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Only key type '{MSTokens.JsonWebAlgorithmsKeyTypes.RSA }' supported.");

            if (jwk.N.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.N), jwk.GetTypeName());
            if (jwk.E.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.E), jwk.GetTypeName());

            var jwkResult = new MSTokens.JsonWebKey();
            jwkResult.Kty = jwk.Kty;
            jwkResult.Use = jwk.Use;

            if (jwk.KeyOps?.Count > 0)
            {
                foreach (var keyOps in jwk.KeyOps)
                {
                    jwkResult.KeyOps.Add(keyOps);
                }
            }

            jwkResult.Alg = jwk.Alg;
            jwkResult.X5u = jwk.X5u;

            if (jwk.X5c?.Count > 0)
            {
                foreach (var x5c in jwk.X5c)
                {
                    jwkResult.X5c.Add(x5c);
                }
            }

            jwkResult.X5t = jwk.X5t;
            jwkResult.Kid = jwk.Kid;

            jwkResult.N = jwk.N;
            jwkResult.E = jwk.E;

            if (includePrivateKey && !jwk.D.IsNullOrEmpty() && !jwk.P.IsNullOrEmpty() && !jwk.Q.IsNullOrEmpty() && !jwk.DP.IsNullOrEmpty() && !jwk.DQ.IsNullOrEmpty() && !jwk.QI.IsNullOrEmpty())
            {
                jwkResult.D = jwk.D;
                jwkResult.P = jwk.P;
                jwkResult.Q = jwk.Q;
                jwkResult.DP = jwk.DP;
                jwkResult.DQ = jwk.DQ;
                jwkResult.QI = jwk.QI;
            }
            return jwkResult;
        }

        /// <summary>
        /// Converts a list of ITfoxtec JWK to a list of Microsoft JWK.
        /// </summary>
        public static IEnumerable<MSTokens.JsonWebKey> ToMSJsonWebKeys(this IEnumerable<JsonWebKey> jwks, bool includePrivateKey = false)
        {
            return jwks.Select(k => k.ToMSJsonWebKey());
        }

        /// <summary>
        /// True if ITfoxtec JWK contains a private key.
        /// </summary>
        public static bool HasPrivateKey(this JsonWebKey jwk)
        {
            if (!jwk.D.IsNullOrEmpty() || !jwk.P.IsNullOrEmpty() || !jwk.Q.IsNullOrEmpty() || !jwk.DP.IsNullOrEmpty() || !jwk.DQ.IsNullOrEmpty() || !jwk.QI.IsNullOrEmpty())
            {
                return true;
            }
            return false;
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
            if (jwk == null) throw new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != MSTokens.JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Key type '{jwk.Kty}' not supported. Only key type '{MSTokens.JsonWebAlgorithmsKeyTypes.RSA }' supported.");

            if (jwk.X5c?.Count() <= 0) throw new ArgumentNullException(nameof(jwk.X5c), jwk.GetTypeName());

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
