using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ITfoxtec.Identity.Tokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace ITfoxtec.Identity.UnitTest
{
    public class JwtHandlerTests
    {
        [Fact]
        public async Task CreateTest()
        {
            var testCertificate = await "test1".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToJsonWebKeyAsync(true);

            var token = JwtHandler.CreateToken(testKey, "test-issuer", new[] { "test-aud" }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            Assert.NotNull(tokenString);
        }

        [Fact]
        public async Task CreateAndValidateTest()
        {
            var testCertificate = await "test1".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToJsonWebKeyAsync(true);

            var issuer = "test-issuer";
            var audience = "test-aud";
            var token = JwtHandler.CreateToken(testKey, issuer, new[] { audience }, new[] { new Claim("sub", "test-user") });
            var tokenString = await token.ToJwtString();

            (ClaimsPrincipal claimsPrincipal, SecurityToken securityToken) = JwtHandler.ValidateToken(tokenString, issuer, new[] { testKey }, audience: audience);

            Assert.True(claimsPrincipal?.Claims?.Count() > 1 );
            Assert.NotNull(securityToken);
        }
    }
}
