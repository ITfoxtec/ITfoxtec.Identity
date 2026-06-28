using ITfoxtec.Identity.Models;
using ITfoxtec.Identity.Tokens;
using MSTokens = Microsoft.IdentityModel.Tokens;
using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace ITfoxtec.Identity.UnitTest
{
    public class X509Certificate2ExtensionsTests
    {
        [Theory]
        [InlineData("P-256")]
        [InlineData("P-384")]
        [InlineData("P-521")]
        public void ToFTJsonWebKey_WithEcdsaCertificate_ReturnsEcJwk(string curveName)
        {
            using var certificate = CreateEcdsaCertificate(curveName);

            var key = certificate.ToFTJsonWebKey();

            Assert.Equal(MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve, key.Kty);
            Assert.Equal(curveName, key.Crv);
            Assert.False(string.IsNullOrWhiteSpace(key.X));
            Assert.False(string.IsNullOrWhiteSpace(key.Y));
            Assert.Null(key.D);
            Assert.Equal(Convert.ToBase64String(certificate.RawData), Assert.Single(key.X5c));
            Assert.Equal(key.Kid, key.X5t);
            Assert.Equal(certificate.GetCertificateX5tS256(), key.X5tS256);
        }

        [Fact]
        public void ToFTJsonWebKey_WithEcdsaPrivateKey_CanRoundTripToCertificateWithPrivateKey()
        {
            using var certificate = CreateEcdsaCertificate("P-256");

            var key = certificate.ToFTJsonWebKey(includePrivateKey: true);
            using var certificateWithPrivateKey = key.ToX509Certificate(includePrivateKey: true);
            using var privateKey = certificateWithPrivateKey.GetECDsaPrivateKey();

            Assert.False(string.IsNullOrWhiteSpace(key.D));
            Assert.True(certificateWithPrivateKey.HasPrivateKey);
            Assert.NotNull(privateKey);
        }

        [Fact]
        public void ToMSJsonWebKey_WithEcdsaPrivateKey_ReturnsEcJwkWithPrivateKey()
        {
            using var certificate = CreateEcdsaCertificate("P-256");

            var key = certificate.ToMSJsonWebKey(includePrivateKey: true);
            using var publicCertificate = key.ToX509Certificate();

            Assert.Equal(MSTokens.JsonWebAlgorithmsKeyTypes.EllipticCurve, key.Kty);
            Assert.Equal("P-256", key.Crv);
            Assert.False(string.IsNullOrWhiteSpace(key.D));
            Assert.False(publicCertificate.HasPrivateKey);
            Assert.NotNull(publicCertificate.GetECDsaPublicKey());
        }

        [Fact]
        public void ToSecurityKey_WithEcdsaJsonWebKey_ReturnsEcdsaSecurityKey()
        {
            using var certificate = CreateEcdsaCertificate("P-256");
            var key = certificate.ToFTJsonWebKey(includePrivateKey: true);

            var securityKey = key.ToSecurityKey();

            Assert.IsType<MSTokens.ECDsaSecurityKey>(securityKey);
            Assert.Equal(key.Kid, securityKey.KeyId);
        }

        [Fact]
        public async Task CreateToken_WithEcdsaJsonWebKey_CanValidateWithPublicJwk()
        {
            using var certificate = CreateEcdsaCertificate("P-256");
            var key = certificate.ToFTJsonWebKey(includePrivateKey: true);
            var issuer = "test-issuer";
            var audience = "test-aud";

            var token = JwtHandler.CreateToken(key, issuer, new[] { audience }, new[] { new Claim("sub", "test-user") }, algorithm: IdentityConstants.Algorithms.Asymmetric.ES256);
            var tokenString = await token.ToJwtString();
            (var claimsPrincipal, var securityToken) = JwtHandler.ValidateToken(tokenString, issuer, new[] { key.GetPublicKey() }, audience: audience);

            Assert.Contains(claimsPrincipal.Claims, c => c.Type == "sub" && c.Value == "test-user");
            Assert.NotNull(securityToken);
        }

        private static X509Certificate2 CreateEcdsaCertificate(string curveName)
        {
            var curve = curveName switch
            {
                "P-256" => ECCurve.NamedCurves.nistP256,
                "P-384" => ECCurve.NamedCurves.nistP384,
                "P-521" => ECCurve.NamedCurves.nistP521,
                _ => throw new NotSupportedException($"Curve '{curveName}' not supported.")
            };

            using var ecdsa = ECDsa.Create(curve);
            var request = new CertificateRequest("CN=ECDSA test", ecdsa, HashAlgorithmName.SHA256);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }
    }
}
