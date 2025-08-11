using System;
using System.Threading.Tasks;
using ITfoxtec.Identity.Helpers;
using Xunit;

namespace ITfoxtec.Identity.UnitTest.Helpers
{
    public class OidcHelperTests
    {
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
