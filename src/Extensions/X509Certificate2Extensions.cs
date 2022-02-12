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
#if NET || NETCORE
        /// <summary>
        /// Create self-signed certificate with subject name. .
        /// </summary>
        /// <param name="subjectName">Certificate subject name, example: "CN=my-certificate, O=some-organisation".</param>
        /// <param name="expiry">Certificate expiry, default 365 days.</param>
        public static Task<X509Certificate2> CreateSelfSignedCertificateAsync(this string subjectName, TimeSpan? expiry = null)
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

                var now = DateTimeOffset.UtcNow;
                return Task.FromResult(certRequest.CreateSelfSigned(now.AddDays(-1), now.Add(expiry ?? TimeSpan.FromDays(365))));
            }
        }
#endif

        /// <summary>
        /// Converts a X509 Certificate to ITfoxtec JWK.
        /// </summary>
        public static JsonWebKey ToFTJsonWebKey(this X509Certificate2 certificate, bool includePrivateKey = false)
        {
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            var jwk = new JsonWebKey();
            jwk.Kty = MSTokens.JsonWebAlgorithmsKeyTypes.RSA;

            var securityKey = new MSTokens.X509SecurityKey(certificate);
            jwk.X5c = new List<string> { Convert.ToBase64String(certificate.RawData) };
            jwk.X5t = WebEncoders.Base64UrlEncode(certificate.GetCertHash());
            jwk.Kid = jwk.X5t;

            var parameters = (securityKey.PublicKey as RSA).ExportParameters(false);
            jwk.N = WebEncoders.Base64UrlEncode(parameters.Modulus);
            jwk.E = WebEncoders.Base64UrlEncode(parameters.Exponent);

            if (includePrivateKey && securityKey.PrivateKeyStatus == MSTokens.PrivateKeyStatus.Exists)
            {
                parameters = (securityKey.PrivateKey as RSA).ExportParameters(true);
                jwk.D = WebEncoders.Base64UrlEncode(parameters.D);
                jwk.P = WebEncoders.Base64UrlEncode(parameters.P);
                jwk.Q = WebEncoders.Base64UrlEncode(parameters.Q);
                jwk.DP = WebEncoders.Base64UrlEncode(parameters.DP);
                jwk.DQ = WebEncoders.Base64UrlEncode(parameters.DQ);
                jwk.QI = WebEncoders.Base64UrlEncode(parameters.InverseQ);
            }
            return jwk;
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

            var jwk = new MSTokens.JsonWebKey();
            jwk.Kty = MSTokens.JsonWebAlgorithmsKeyTypes.RSA;

            var securityKey = new MSTokens.X509SecurityKey(certificate);
            jwk.X5c.Add(Convert.ToBase64String(certificate.RawData));
            jwk.X5t = WebEncoders.Base64UrlEncode(certificate.GetCertHash());
            jwk.Kid = jwk.X5t;

            var parameters = (securityKey.PublicKey as RSA).ExportParameters(false);
            jwk.N = WebEncoders.Base64UrlEncode(parameters.Modulus);
            jwk.E = WebEncoders.Base64UrlEncode(parameters.Exponent);

            if (includePrivateKey && securityKey.PrivateKeyStatus == MSTokens.PrivateKeyStatus.Exists)
            {
                parameters = (securityKey.PrivateKey as RSA).ExportParameters(true);
                jwk.D = WebEncoders.Base64UrlEncode(parameters.D);
                jwk.P = WebEncoders.Base64UrlEncode(parameters.P);
                jwk.Q = WebEncoders.Base64UrlEncode(parameters.Q);
                jwk.DP = WebEncoders.Base64UrlEncode(parameters.DP);
                jwk.DQ = WebEncoders.Base64UrlEncode(parameters.DQ);
                jwk.QI = WebEncoders.Base64UrlEncode(parameters.InverseQ);
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
    }
}
