using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

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
        /// Converts a X509 Certificate to JWK.
        /// </summary>
        public static Task<JsonWebKey> ToJsonWebKeyAsync(this X509Certificate2 certificate, bool includePrivateKey = false)
        {
            if (certificate == null) new ArgumentNullException(nameof(certificate));

            var jwk = new JsonWebKey();
            jwk.Kty = JsonWebAlgorithmsKeyTypes.RSA;

            var securityKey = new X509SecurityKey(certificate);
            jwk.KeyId = securityKey.KeyId;
            jwk.X5c.Add(Convert.ToBase64String(certificate.RawData));
            jwk.X5t = WebEncoders.Base64UrlEncode(certificate.GetCertHash());

            var parameters = (securityKey.PublicKey as RSA).ExportParameters(false);
            jwk.N = WebEncoders.Base64UrlEncode(parameters.Modulus);
            jwk.E = WebEncoders.Base64UrlEncode(parameters.Exponent);

            if (includePrivateKey && securityKey.PrivateKeyStatus == PrivateKeyStatus.Exists)
            {
                parameters = (securityKey.PrivateKey as RSA).ExportParameters(true);
                jwk.D = WebEncoders.Base64UrlEncode(parameters.D);
                jwk.P = WebEncoders.Base64UrlEncode(parameters.P);
                jwk.Q = WebEncoders.Base64UrlEncode(parameters.Q);
                jwk.DP = WebEncoders.Base64UrlEncode(parameters.DP);
                jwk.DQ = WebEncoders.Base64UrlEncode(parameters.DQ);
                jwk.QI = WebEncoders.Base64UrlEncode(parameters.InverseQ);
            }
            return Task.FromResult(jwk);
        }
    }
}
