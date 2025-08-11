using System;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using MSTokens = Microsoft.IdentityModel.Tokens;
using ITfoxtec.Identity.Models;
using System.Collections.Generic;
using ITfoxtec.Identity.Util;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for ITfoxtec JsonWebKey.
    /// </summary>
    public static class FTJsonWebKeyExtensions
    {
        /// <summary>
        /// Get public JWK.
        /// </summary>
        public static JsonWebKey GetPublicKey(this JsonWebKey jwk)
        {
            var publicKey = new JsonWebKey
            {
                Kty = jwk.Kty,
                Use = jwk.Use,
                Kid = jwk.Kid,
                Alg = jwk.Alg,
            };

            if (jwk.X5c?.Count() > 0)
            {
                publicKey.X5c = new List<string> { jwk.X5c.First() };
            }

            publicKey.X5t = jwk.X5t;
            publicKey.X5tS256 = jwk.X5tS256;

            if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.RSA)
            {

                publicKey.N = jwk.N;
                publicKey.E = jwk.E;
            }
            else if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve)
            {
                publicKey.Crv = jwk.Crv;
                publicKey.X = jwk.X;
                publicKey.Y = jwk.Y;
            }
            
            return publicKey;
        }

        /// <summary>
        /// Converts a JWK to RSA parameters.
        /// </summary>
        public static RSAParameters ToRsaParameters(this JsonWebKey jwk, bool includePrivateParameters = false)
        {
            if (jwk == null) throw new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != MSTokens.JsonWebAlgorithmsKeyTypes.RSA) throw new NotSupportedException($"Only key type '{MSTokens.JsonWebAlgorithmsKeyTypes.RSA}' supported.");

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

            if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.RSA)
            {
                if (jwk.N.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.N), jwk.GetTypeName());
                if (jwk.E.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.E), jwk.GetTypeName());
            }
            else if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve)
            {
                if (jwk.Crv.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.Crv), jwk.GetTypeName());
                if (jwk.X.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.X), jwk.GetTypeName());
                if (jwk.Y.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.Y), jwk.GetTypeName());
            }
            else
            {
                throw new NotSupportedException($"Key type '{jwk.Kty}' not supported.");
            }

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

            jwkResult.Kid = jwk.Kid;
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
            jwkResult.X5tS256 = jwk.X5tS256;

            if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.RSA)
            {
                jwkResult.N = jwk.N;
                jwkResult.E = jwk.E;
            }
            else if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve)
            {
                jwkResult.Crv = jwk.Crv;
                jwkResult.X = jwk.X;
                jwkResult.Y = jwk.Y;
            }

            if (includePrivateKey)
            {
                if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.RSA &&
                    !jwk.D.IsNullOrEmpty() && !jwk.P.IsNullOrEmpty() && !jwk.Q.IsNullOrEmpty() && !jwk.DP.IsNullOrEmpty() && !jwk.DQ.IsNullOrEmpty() && !jwk.QI.IsNullOrEmpty())
                {
                    jwkResult.D = jwk.D;
                    jwkResult.P = jwk.P;
                    jwkResult.Q = jwk.Q;
                    jwkResult.DP = jwk.DP;
                    jwkResult.DQ = jwk.DQ;
                    jwkResult.QI = jwk.QI;
                }
                else if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve && !jwk.D.IsNullOrEmpty())
                {
                    jwkResult.D = jwk.D;
                }
            }
            return jwkResult;
        }

        /// <summary>
        /// Converts a list of ITfoxtec JWK to a list of Microsoft JWK.
        /// </summary>
        public static IEnumerable<MSTokens.JsonWebKey> ToMSJsonWebKeys(this IEnumerable<JsonWebKey> jwks, bool includePrivateKey = false)
        {
            return jwks.Select(k => k.ToMSJsonWebKey(includePrivateKey));
        }

        /// <summary>
        /// True if ITfoxtec JWK contains a private key.
        /// </summary>
        public static bool HasPrivateKey(this JsonWebKey jwk)
        {
            if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.RSA &&
                (!jwk.D.IsNullOrEmpty() || !jwk.P.IsNullOrEmpty() || !jwk.Q.IsNullOrEmpty() || !jwk.DP.IsNullOrEmpty() || !jwk.DQ.IsNullOrEmpty() || !jwk.QI.IsNullOrEmpty()))
            {
                return true;
            }
            else if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve && !jwk.D.IsNullOrEmpty())
            {
                return true;
            }
            return false;
        }

#if !NETSTANDARD
        /// <summary>
        /// Converts a JWK to RSA.
        /// </summary>
        public static RSA ToRsa(this JsonWebKey jwk, bool includePrivateParameters = false)
        {
            return RSA.Create(jwk.ToRsaParameters(includePrivateParameters));
        }

        /// <summary>
        /// Converts an EC JWK to ECDsa.
        /// </summary>
        public static ECDsa ToEcdsa(this JsonWebKey jwk, bool includePrivateParameters = false)
        {
            if (jwk == null) throw new ArgumentNullException(nameof(jwk));
            if (jwk.Kty != MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve)
                throw new NotSupportedException($"Only key type '{MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve}' supported.");

            if (jwk.Crv.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.Crv), jwk.GetTypeName());
            if (jwk.X.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.X), jwk.GetTypeName());
            if (jwk.Y.IsNullOrEmpty()) throw new ArgumentNullException(nameof(jwk.Y), jwk.GetTypeName());

            var curve = jwk.Crv switch
            {
                "P-256" => ECCurve.NamedCurves.nistP256,
                "P-384" => ECCurve.NamedCurves.nistP384,
                "P-521" => ECCurve.NamedCurves.nistP521,
                _ => throw new NotSupportedException($"Curve '{jwk.Crv}' not supported.")
            };

            var x = WebEncoders.Base64UrlDecode(jwk.X);
            var y = WebEncoders.Base64UrlDecode(jwk.Y);

            int expectedLen = curve.Oid.FriendlyName switch
            {
                "nistP256" => 32,
                "nistP384" => 48,
                "nistP521" => 66,
                _ => throw new NotSupportedException($"Curve '{curve.Oid.FriendlyName}' not supported.")
            };

            static byte[] LeftPad(byte[] input, int size)
            {
                if (input.Length == size) return input;
                if (input.Length > size) throw new ArgumentException("Input length is larger than expected size.");
                var padded = new byte[size];
                Buffer.BlockCopy(input, 0, padded, size - input.Length, input.Length);
                return padded;
            }

            var ecParams = new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = LeftPad(x, expectedLen),
                    Y = LeftPad(y, expectedLen)
                }
            };

            if (includePrivateParameters && !jwk.D.IsNullOrEmpty())
            {
                var d = WebEncoders.Base64UrlDecode(jwk.D);
                ecParams.D = LeftPad(d, expectedLen);
            }

            var ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(ecParams);
            return ecdsa;
        }
#endif

        /// <summary>
        /// Converts a JWK to public X509Certificate.
        /// </summary>
        public static X509Certificate2 ToX509Certificate(this JsonWebKey jwk
#if !NETSTANDARD
        , bool includePrivateKey = false
#endif
        )
        {
            if (jwk == null) throw new ArgumentNullException(nameof(jwk));
            if (!(jwk.X5c?.Count() > 0)) throw new ArgumentNullException(nameof(jwk.X5c), jwk.GetTypeName());

            var cert = CertificateUtil.LoadBytes(jwk.X5c.First());
#if !NETSTANDARD
            if (includePrivateKey)
            {
                // RSA branch with complete private parameters
                if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.RSA &&
                    !jwk.D.IsNullOrEmpty() && !jwk.P.IsNullOrEmpty() && !jwk.Q.IsNullOrEmpty() &&
                    !jwk.DP.IsNullOrEmpty() && !jwk.DQ.IsNullOrEmpty() && !jwk.QI.IsNullOrEmpty())
                {
                    using (var rsa = jwk.ToRsa(includePrivateParameters: true))
                    {
                        using var certWithKey = cert.CopyWithPrivateKey(rsa);
                        cert.Dispose();

                        // Re-import as PFX with PersistKeySet so Windows assigns a key container usable by mTLS
                        var pfxBytes = certWithKey.Export(X509ContentType.Pkcs12);
                        return CertificateUtil.LoadBytes(pfxBytes,
                            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
                    }
                }
                // ECDSA branch with D present
                else if (jwk.Kty == MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve && !jwk.D.IsNullOrEmpty())
                {
                    using (var ecdsa = jwk.ToEcdsa(includePrivateParameters: true))
                    {
                        using var certWithKey = cert.CopyWithPrivateKey(ecdsa);
                        cert.Dispose();

                        // Re-import as PFX with PersistKeySet (same reasoning as RSA)
                        var pfxBytes = certWithKey.Export(X509ContentType.Pkcs12);
                        return CertificateUtil.LoadBytes(pfxBytes,
                            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
                    }
                }
            }
#endif
            return cert;
        }
    }
}
