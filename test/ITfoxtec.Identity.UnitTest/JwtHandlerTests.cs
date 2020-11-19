using System.Security.Claims;
using System.Threading.Tasks;
using ITfoxtec.Identity.Tokens;
using Xunit;

namespace ITfoxtec.Identity.UnitTest
{
    public class JwtHandlerTests
    {
        [Fact]
        public async Task Test1()
        {
            var testCertificate = await "test1".CreateSelfSignedCertificateAsync();
            var testKey = await testCertificate.ToJsonWebKeyAsync(true);

            var token = JwtHandler.CreateToken(testKey, "test-issuer", new[] { "test-aud" }, new[] { new Claim("sub", "test-user") });
            var tokenString = token.ToJwtString();

            Assert.NotNull(tokenString);
        }
    }
}
