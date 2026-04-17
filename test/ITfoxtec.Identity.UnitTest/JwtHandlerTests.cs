using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ITfoxtec.Identity.Tokens;
using MSTokens = Microsoft.IdentityModel.Tokens;
using Xunit;
using ITfoxtec.Identity.Models;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace ITfoxtec.Identity.UnitTest
{
    public class JwtHandlerTests
    {
        [Fact]
        public async Task MSKidTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToMSJsonWebKeyAsync(true);

            Assert.Equal(testKey.X5t, testKey.Kid);
            Assert.Equal(testKey.X5t, testKey.KeyId);
        }

        [Fact]
        public async Task FTKidTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToFTJsonWebKeyAsync(true);

            Assert.Equal(testKey.X5t, testKey.Kid);
        }

        [Fact]
        public async Task MSCreateTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToMSJsonWebKeyAsync(true);

            var token = JwtHandler.CreateToken(testKey, "test-issuer", new[] { "test-aud" }, new[] { new Claim("sub", "test-user") }, typ: IdentityConstants.JwtHeaders.MediaTypes.AtJwt);
            var tokenString = await token.ToJwtString();

            Assert.NotNull(tokenString);
        }

        [Fact]
        public async Task FTCreateTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToFTJsonWebKeyAsync(true);

            var token = JwtHandler.CreateToken(testKey, "test-issuer", new[] { "test-aud" }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            Assert.NotNull(tokenString);
        }

        [Fact]
        public async Task CreateTokenIssuesAuthTimeAsInteger64Test()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToFTJsonWebKeyAsync(true);

            var authTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var token = JwtHandler.CreateToken(testKey, "test-issuer", new[] { "test-aud" }, new[]
            {
                new Claim(JwtClaimTypes.Subject, "test-user"),
                new Claim(JwtClaimTypes.AuthTime, authTime)
            });

            var authTimeClaim = token.Claims.Single(c => c.Type == JwtClaimTypes.AuthTime);

            Assert.Equal(ClaimValueTypes.Integer64, authTimeClaim.ValueType);
            Assert.IsType<long>(token.Payload[JwtClaimTypes.AuthTime]);
            Assert.Equal(long.Parse(authTime), token.Payload[JwtClaimTypes.AuthTime]);
        }

        [Fact]
        public async Task CreateTokenIssuesAmrAsArrayTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToFTJsonWebKeyAsync(true);

            var token = JwtHandler.CreateToken(testKey, "test-issuer", new[] { "test-aud" }, new[]
            {
                new Claim(JwtClaimTypes.Subject, "test-user"),
                new Claim(JwtClaimTypes.Amr, "pwd")
            });
            var tokenString = await token.ToJwtString();

            var payload = JObject.Parse(MSTokens.Base64UrlEncoder.Decode(tokenString.Split('.')[1]));
            var amrClaim = payload[JwtClaimTypes.Amr];

            Assert.NotNull(amrClaim);
            Assert.Equal(JTokenType.Array, amrClaim.Type);
            Assert.Equal(new[] { "pwd" }, amrClaim.Values<string>());
        }

        [Fact]
        public async Task MSCreateAndValidateTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToMSJsonWebKeyAsync(true);

            var issuer = "test-issuer";
            var audience = "test-aud";
            var token = JwtHandler.CreateToken(testKey, issuer, new[] { audience }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            (ClaimsPrincipal claimsPrincipal, MSTokens.SecurityToken securityToken) = JwtHandler.ValidateToken(tokenString, issuer, new[] { testKey }, audience: audience);

            Assert.True(claimsPrincipal?.Claims?.Count() > 1);
            Assert.NotNull(securityToken);
        }

        [Fact]
        public async Task FTCreateAndValidateTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToFTJsonWebKeyAsync(true);

            var issuer = "test-issuer";
            var audience = "test-aud";
            var token = JwtHandler.CreateToken(testKey, issuer, new[] { audience }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            (ClaimsPrincipal claimsPrincipal, MSTokens.SecurityToken securityToken) = JwtHandler.ValidateToken(tokenString, issuer, new[] { testKey }, audience: audience);

            Assert.True(claimsPrincipal?.Claims?.Count() > 1);
            Assert.NotNull(securityToken);
        }

        [Fact]
        public async Task MSCreateAndNotValidateTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToMSJsonWebKeyAsync(true);

            var issuer = "test-issuer";
            var audience = "test-aud";
            var token = JwtHandler.CreateToken(testKey, issuer, new[] { audience }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            var claimsPrincipal = JwtHandler.ReadTokenClaims(tokenString);

            Assert.True(claimsPrincipal?.Claims?.Count() > 1);
        }

        [Fact]
        public async Task FTCreateAndNotValidateTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToFTJsonWebKeyAsync(true);

            var issuer = "test-issuer";
            var audience = "test-aud";
            var token = JwtHandler.CreateToken(testKey, issuer, new[] { audience }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            var claimsPrincipal = JwtHandler.ReadTokenClaims(tokenString);

            Assert.True(claimsPrincipal?.Claims?.Count() > 1);
        }

        [Fact]
        public async Task MSCreateAndOidcDiscoveryValidateTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToMSJsonWebKeyAsync(true);

            var issuer = "test-issuer";
            var audience = "test-aud";
            var token = JwtHandler.CreateToken(testKey, issuer, new[] { audience }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            var jsonWebKeySetAsJson = GetOidcDiscoveryJsonWebKeySet(testKey.ToFTJsonWebKey());
            var jsonWebKeySet = jsonWebKeySetAsJson.ToObject<JsonWebKeySet>();
            (ClaimsPrincipal claimsPrincipal, MSTokens.SecurityToken securityToken) = JwtHandler.ValidateToken(tokenString, issuer, jsonWebKeySet.Keys.ToMSJsonWebKeys(), audience: audience);

            Assert.True(claimsPrincipal?.Claims?.Count() > 1);
            Assert.NotNull(securityToken);
        }

        [Fact]
        public async Task FTCreateAndOidcDiscoveryValidateTest()
        {
            var testCertificate = await "CN=test1, O=Test".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToFTJsonWebKeyAsync(true);

            var issuer = "test-issuer";
            var audience = "test-aud";
            var token = JwtHandler.CreateToken(testKey, issuer, new[] { audience }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            var jsonWebKeySetAsJson = GetOidcDiscoveryJsonWebKeySet(testKey);
            var jsonWebKeySet = jsonWebKeySetAsJson.ToObject<JsonWebKeySet>();
            (ClaimsPrincipal claimsPrincipal, MSTokens.SecurityToken securityToken) = JwtHandler.ValidateToken(tokenString, issuer, jsonWebKeySet.Keys.ToMSJsonWebKeys(), audience: audience);

            Assert.True(claimsPrincipal?.Claims?.Count() > 1);
            Assert.NotNull(securityToken);
        }

        private string GetOidcDiscoveryJsonWebKeySet(JsonWebKey testKey)
        {
            var jonWebKeySet = new JsonWebKeySet() { Keys = new List<JsonWebKey>() };
            jonWebKeySet.Keys.Add(testKey.GetPublicKey());

            return jonWebKeySet.ToJsonIndented();
        }
    }
}
