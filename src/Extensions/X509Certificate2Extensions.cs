using Microsoft.AspNetCore.WebUtilities;
using MSTokens = Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ITfoxtec.Identity.Models;
using System.Collections.Generic;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for X509Certificate2.
    /// </summary>
    public static class X509Certificate2Extensions
    {
#if !NETSTANDARD
        /// <summary>
        /// Create self-signed certificate with subject name. .
        /// </summary>
        /// <param name="subjectName">Certificate subject name, example: "CN=my-certificate, O=some-organisation".</param>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        public static Task<X509Certificate2> CreateSelfSignedCertificateAsync(this string subjectName, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            using (var rsa = RSA.Create(2048))
            {
                var certRequest = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                certRequest.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));

                certRequest.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));

                certRequest.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyAgreement,
                        false));

                return Task.FromResult(certRequest.CreateSelfSigned(notBefore, notAfter));
            }
        }

        /// <summary>
        /// Create self-signed certificate with subject name. .
        /// </summary>
        /// <param name="subjectName">Certificate subject name, example: "CN=my-certificate, O=some-organisation".</param>
        /// <param name="expiry">Certificate expiry, default 1 year.</param>
        public static Task<X509Certificate2> CreateSelfSignedCertificateAsync(this string subjectName, TimeSpan? expiry = null)
        {
            var now = DateTimeOffset.UtcNow;
            return subjectName.CreateSelfSignedCertificateAsync(now.AddSeconds(-5), expiry.HasValue ? now.Add(expiry.Value) : now.AddYears(1));
        }
#endif

        /// <summary>
        /// Converts a X509 Certificate to ITfoxtec JWK.
        /// </summary>
        public static JsonWebKey ToFTJsonWebKey(this X509Certificate2 certificate, bool includePrivateKey = false)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            var jwk = new JsonWebKey
            {
                Kid = WebEncoders.Base64UrlEncode(certificate.GetCertHash()),
                X5c = new List<string> { Convert.ToBase64String(certificate.RawData) }
            };
            jwk.X5t = jwk.Kid;
            jwk.X5tS256 = certificate.GetCertificateX5tS256();

            var securityKey = new MSTokens.X509SecurityKey(certificate);
            if (securityKey.PublicKey is RSA rsaPublicKey)
            {
                jwk.Kty = MSTokens.JsonWebAlgorithmsKeyTypes.RSA;
                var parameters = rsaPublicKey.ExportParameters(false);
                jwk.N = WebEncoders.Base64UrlEncode(parameters.Modulus);
                jwk.E = WebEncoders.Base64UrlEncode(parameters.Exponent);

                if (includePrivateKey && securityKey.PrivateKey is RSA rsaPrivateKey)
                {
                    parameters = rsaPrivateKey.ExportParameters(true);
                    jwk.D = WebEncoders.Base64UrlEncode(parameters.D);
                    jwk.P = WebEncoders.Base64UrlEncode(parameters.P);
                    jwk.Q = WebEncoders.Base64UrlEncode(parameters.Q);
                    jwk.DP = WebEncoders.Base64UrlEncode(parameters.DP);
                    jwk.DQ = WebEncoders.Base64UrlEncode(parameters.DQ);
                    jwk.QI = WebEncoders.Base64UrlEncode(parameters.InverseQ);
                }
            }
            else if (securityKey.PublicKey is ECDsa ecdsaPublicKey)
            {
                jwk.Kty = MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve;
                var parameters = ecdsaPublicKey.ExportParameters(false);
                jwk.Crv = GetJsonWebKeyCurve(parameters.Curve);
                jwk.X = WebEncoders.Base64UrlEncode(parameters.Q.X);
                jwk.Y = WebEncoders.Base64UrlEncode(parameters.Q.Y);

                if (includePrivateKey && securityKey.PrivateKey is ECDsa ecdsaPrivateKey)
                {
                    parameters = ecdsaPrivateKey.ExportParameters(true);
                    jwk.D = WebEncoders.Base64UrlEncode(parameters.D);
                }
            }
            else
            {
                throw new NotSupportedException($"Certificate public key type '{securityKey.PublicKey?.GetType().FullName}' is not supported.");
            }
            return jwk;
        }

        /// <summary>
        /// X.509 certificate SHA-256 thumbprint. A base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280]. 
        /// </summary>
        public static string GetCertificateX5tS256(this X509Certificate2 certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            return GetCertificateX5tS256(certificate.RawData);
        }

        /// <summary>
        /// X.509 certificate SHA-256 thumbprint. A base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280]. 
        /// </summary>
        public static string GetCertificateX5tS256(this byte[] certificate)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(certificate);
                return WebEncoders.Base64UrlEncode(hash);
            }
        }

        /// <summary>
        /// Converts a X509 Certificate to ITfoxtec JWK.
        /// </summary>
        public static Task<JsonWebKey> ToFTJsonWebKeyAsync(this X509Certificate2 certificate, bool includePrivateKey = false)
        {
            var key = ToFTJsonWebKey(certificate, includePrivateKey);
            return Task.FromResult(key);
        }

        /// <summary>
        /// Converts a X509 Certificate to Microsoft JWK.
        /// </summary>
        public static MSTokens.JsonWebKey ToMSJsonWebKey(this X509Certificate2 certificate, bool includePrivateKey = false)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            var jwk = new MSTokens.JsonWebKey
            {
                Kid = WebEncoders.Base64UrlEncode(certificate.GetCertHash())
            };
            jwk.X5c.Add(Convert.ToBase64String(certificate.RawData));
            jwk.X5t = jwk.Kid;
            jwk.X5tS256 = certificate.GetCertificateX5tS256();

            var securityKey = new MSTokens.X509SecurityKey(certificate);
            if (securityKey.PublicKey is RSA rsaPublicKey)
            {
                jwk.Kty = MSTokens.JsonWebAlgorithmsKeyTypes.RSA;
                var parameters = rsaPublicKey.ExportParameters(false);
                jwk.N = WebEncoders.Base64UrlEncode(parameters.Modulus);
                jwk.E = WebEncoders.Base64UrlEncode(parameters.Exponent);

                if (includePrivateKey && securityKey.PrivateKey is RSA rsaPrivateKey)
                {
                    parameters = rsaPrivateKey.ExportParameters(true);
                    jwk.D = WebEncoders.Base64UrlEncode(parameters.D);
                    jwk.P = WebEncoders.Base64UrlEncode(parameters.P);
                    jwk.Q = WebEncoders.Base64UrlEncode(parameters.Q);
                    jwk.DP = WebEncoders.Base64UrlEncode(parameters.DP);
                    jwk.DQ = WebEncoders.Base64UrlEncode(parameters.DQ);
                    jwk.QI = WebEncoders.Base64UrlEncode(parameters.InverseQ);
                }
            }
            else if (securityKey.PublicKey is ECDsa ecdsaPublicKey)
            {
                jwk.Kty = MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve;
                var parameters = ecdsaPublicKey.ExportParameters(false);
                jwk.Crv = GetJsonWebKeyCurve(parameters.Curve);
                jwk.X = WebEncoders.Base64UrlEncode(parameters.Q.X);
                jwk.Y = WebEncoders.Base64UrlEncode(parameters.Q.Y);

                if (includePrivateKey && securityKey.PrivateKey is ECDsa ecdsaPrivateKey)
                {
                    parameters = ecdsaPrivateKey.ExportParameters(true);
                    jwk.D = WebEncoders.Base64UrlEncode(parameters.D);
                }
            }
            else
            {
                throw new NotSupportedException($"Certificate public key type '{securityKey.PublicKey?.GetType().FullName}' is not supported.");
            }
            return jwk;
        }

        /// <summary>
        /// Converts a X509 Certificate to Microsoft JWK.
        /// </summary>
        public static Task<MSTokens.JsonWebKey> ToMSJsonWebKeyAsync(this X509Certificate2 certificate, bool includePrivateKey = false)
        {
            var key = ToMSJsonWebKey(certificate, includePrivateKey);
            return Task.FromResult(key);
        }

        private static string GetJsonWebKeyCurve(ECCurve curve)
        {
            switch (curve.Oid.Value ?? curve.Oid.FriendlyName)
            {
                case "1.2.840.10045.3.1.7":
                case "nistP256":
                    return "P-256";
                case "1.3.132.0.34":
                case "nistP384":
                    return "P-384";
                case "1.3.132.0.35":
                case "nistP521":
                    return "P-521";
                default:
                    throw new NotSupportedException($"ECDSA certificate curve '{curve.Oid.FriendlyName ?? curve.Oid.Value}' is not supported.");
            }
        }
    }
}
