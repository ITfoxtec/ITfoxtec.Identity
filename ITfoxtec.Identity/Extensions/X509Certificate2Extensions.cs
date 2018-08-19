using ITfoxtec.Identity.Discovery;
using Microsoft.AspNetCore.WebUtilities;
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
        /// <summary>
        /// Converts a X509 Certificate to JWK.
        /// </summary>
        public static Task<JsonWebKey> ToJsonWebKey(this X509Certificate2 certificate, bool includePrivateKey = false)
        {
            if (certificate == null) new ArgumentNullException(nameof(certificate));

            var jwk = new JsonWebKey();
            jwk.KeyType = IdentityConstants.JsonWebKeyTypes.RSA;

            var securityKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey(certificate);
            jwk.KeyId = securityKey.KeyId;
            jwk.X509CertificateChain = new[] { Convert.ToBase64String(certificate.RawData) };
            jwk.X509CertificateSHA1Thumbprint = WebEncoders.Base64UrlEncode(certificate.GetCertHash());

            var parameters = (securityKey.PublicKey as RSA).ExportParameters(false);
            jwk.Modulus = WebEncoders.Base64UrlEncode(parameters.Modulus);
            jwk.Exponent = WebEncoders.Base64UrlEncode(parameters.Exponent);

            if (includePrivateKey && securityKey.PrivateKeyStatus == Microsoft.IdentityModel.Tokens.PrivateKeyStatus.Exists)
            {
                parameters = (securityKey.PrivateKey as RSA).ExportParameters(true);
                jwk.D = WebEncoders.Base64UrlEncode(parameters.D);
                jwk.P = WebEncoders.Base64UrlEncode(parameters.P);
                jwk.Q = WebEncoders.Base64UrlEncode(parameters.Q);
                jwk.DP = WebEncoders.Base64UrlEncode(parameters.DP);
                jwk.DQ = WebEncoders.Base64UrlEncode(parameters.DQ);
                jwk.InverseQ = WebEncoders.Base64UrlEncode(parameters.InverseQ);
            }
            return Task.FromResult(jwk);
        }
    }
}
