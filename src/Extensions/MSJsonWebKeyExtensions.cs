using System;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using FTModels = ITfoxtec.Identity.Models;
using System.Collections.Generic;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for Microsoft JsonWebKey.
    /// </summary>
    public static class MSJsonWebKeyExtensions
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
                publicKey.X5c.Add(jwk.X5c.First());
            }
            return publicKey;
        }

        /// <summary>
        /// Converts a JWK to RSA parameters.
        /// </summary>
        public static RSAParameters ToRsaParameters(this JsonWebKey jwk, bool includePrivateParameters = false)
        {
            if (jwk == null) throw new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Only key type '{JsonWebAlgorithmsKeyTypes.RSA }' supported.");

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
        /// Converts a JWK to a SecurityKey.
        /// </summary>
        public static SecurityKey ToSecurityKey(this JsonWebKey jwk)
        {
            var key = new RsaSecurityKey(jwk.ToRsaParameters(true));
            key.KeyId = jwk.Kid;
            return key;
        }

        /// <summary>
        /// Converts a Microsoft JWK to a ITfoxtec JWK.
        /// </summary>
        public static FTModels.JsonWebKey ToFTJsonWebKey(this JsonWebKey jwk, bool includePrivateKey = false)
        {
            if (jwk == null) throw new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Only key type '{JsonWebAlgorithmsKeyTypes.RSA }' supported.");

            if (jwk.N.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.N), jwk.GetTypeName());
            if (jwk.E.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.E), jwk.GetTypeName());

            var jwkResult = new FTModels.JsonWebKey();
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
                jwkResult.X5c = new List<string>();
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
            if (jwk.Kty != JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Key type '{jwk.Kty}' not supported. Only key type '{JsonWebAlgorithmsKeyTypes.RSA }' supported.");

            if (jwk.X5c?.Count() <= 0) throw new ArgumentNullException(nameof(jwk.X5c), jwk.GetTypeName());

            var certificate = new X509Certificate2(Convert.FromBase64String(jwk.X5c.First()));
            if (!jwk.X5t.IsNullOrEmpty())
            {
                if (!jwk.X5t.Equals(certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception($"X.509 certificate x5t SHA-1 thumbprint '{jwk.X5t}' do not match certificate thumbprint '{certificate.Thumbprint}'.");
                }
            }

            return certificate;
        }
    }
}
