using System;
using System.Threading.Tasks;
using ITfoxtec.Identity.Helpers;
using Xunit;

namespace ITfoxtec.Identity.UnitTest.Helpers
{
    public class OidcHelperTests
    {
        [Theory]
        [InlineData("RS256", "oFYf1knNtrqnhAVfBRuteQ")]
        [InlineData("RS384", "SeGOaEgS6QNKbB7vkLM3y8nujeY4Ple3")]
        [InlineData("RS512", "kyd4-h3ZoV2sH212kLKbcOnCBajStKQ38Ae_bfT-PFI")]
        public async Task LeftMostBase64urlEncodedHash_UsesLeftHalfOfSigningAlgorithmDigest(string algorithm, string expected)
        {
            Assert.Equal(expected, "access".LeftMostBase64urlEncodedHash(algorithm));
            Assert.Equal(expected, await "access".LeftMostBase64urlEncodedHashAsync(algorithm));
        }

        [Theory]
        [InlineData("none")]
        [InlineData("HS256")]
        [InlineData("rs384")]
        [InlineData(null)]
        public void LeftMostBase64urlEncodedHash_RejectsUnsupportedAlgorithm(string algorithm)
        {
            Assert.Throws<NotSupportedException>(() => "access".LeftMostBase64urlEncodedHash(algorithm));
        }

        [Fact]
        public async Task ValidateOidcWithUserInfoEndpoint_ThrowsForNullIdToken()
        {
            var helper = new OidcHelper(httpClientFactory: null, oidcDiscoveryHandler: null);

            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                helper.ValidateOidcWithUserInfoEndpoint(idToken: null, accessToken: "access-token"));
        }

        [Fact]
        public async Task ValidateOidcWithUserInfoEndpoint_ThrowsForNullAccessToken()
        {
            var helper = new OidcHelper(httpClientFactory: null, oidcDiscoveryHandler: null);

            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                helper.ValidateOidcWithUserInfoEndpoint(idToken: "id-token", accessToken: null));
        }
    }
}
