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
            var jsonWebKey = new JsonWebKey();
            jsonWebKey.KeyType = IdentityConstants.JsonWebKeyTypes.RSA;

            var securityKey = new Microsoft.IdentityModel.Tokens.X509SecurityKey(certificate);
            jsonWebKey.KeyId = securityKey.KeyId;
            jsonWebKey.X509CertificateChain = new[] { Convert.ToBase64String(certificate.RawData) };
            jsonWebKey.X509CertificateSHA1Thumbprint = WebEncoders.Base64UrlEncode(certificate.GetCertHash());

            var parameters = (securityKey.PublicKey as RSA).ExportParameters(false);
            jsonWebKey.Modulus = WebEncoders.Base64UrlEncode(parameters.Modulus);
            jsonWebKey.Exponent = WebEncoders.Base64UrlEncode(parameters.Exponent);

            if (includePrivateKey && securityKey.PrivateKeyStatus == Microsoft.IdentityModel.Tokens.PrivateKeyStatus.Exists)
            {
                parameters = (securityKey.PrivateKey as RSA).ExportParameters(true);
                jsonWebKey.D = WebEncoders.Base64UrlEncode(parameters.D);
                jsonWebKey.P = WebEncoders.Base64UrlEncode(parameters.P);
                jsonWebKey.Q = WebEncoders.Base64UrlEncode(parameters.Q);
                jsonWebKey.DP = WebEncoders.Base64UrlEncode(parameters.DP);
                jsonWebKey.DQ = WebEncoders.Base64UrlEncode(parameters.DQ);
                jsonWebKey.InverseQ = WebEncoders.Base64UrlEncode(parameters.InverseQ);
            }
            return Task.FromResult(jsonWebKey);
        }
    }
}
