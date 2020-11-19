using ITfoxtec.Identity.Messages;
using System;
using System.Linq;
using Xunit;

namespace ITfoxtec.Identity.UnitTest
{
    public class ResourceRequestTest
    {
        [Theory]
        [InlineData("https://someapi.com/")]
        //[InlineData("https://someapi.com/", "https://someapi.com/")]
        public void Test1(params string[] resources)
        {
            var authenticationRequest = new AuthenticationRequest
            {
                ClientId = "clientx",
                ResponseMode = IdentityConstants.ResponseModes.FormPost,
                ResponseType = IdentityConstants.ResponseTypes.Code,
                RedirectUri = "https://sometest.com",
                Scope = "somescope",
                Nonce = "xxx",
                State = "xxx"
            };

            var resourceRequest = new ResourceRequest
            {
                Resources = resources
            };

            resourceRequest.Validate();

            var nameValueCollection = authenticationRequest.ToDictionary().AddToDictionary(resourceRequest);
            Assert.Equal(7 + resources.Count(), nameValueCollection.Count);
        }

        [Fact]
        public void Test2()
        {
            var authenticationRequest = new AuthenticationRequest
            {
                ClientId = "clientx",
                ResponseMode = IdentityConstants.ResponseModes.FormPost,
                ResponseType = IdentityConstants.ResponseTypes.Code,
                RedirectUri = "https://sometest.com",
                Scope = "somescope",
                Nonce = "xxx",
                State = "xxx"
            };

            var resourceRequest = new ResourceRequest
            {
                Resources = new[] { "https://someapi.com/", "https://someapi2.com/", "" }
            };

            Action testCode = () => { resourceRequest.Validate(); };

            var exc = Record.Exception(testCode);

            Assert.NotNull(exc);
        }

        [Fact]
        public void Test3()
        {
            var authenticationRequest = new AuthenticationRequest
            {
                ClientId = "clientx",
                ResponseMode = IdentityConstants.ResponseModes.FormPost,
                ResponseType = IdentityConstants.ResponseTypes.Code,
                RedirectUri = "https://sometest.com",
                Scope = "somescope",
                Nonce = "xxx",
                State = "xxx"
            };

            var resourceRequest = new ResourceRequest
            {
                Resources = new string[] { }
            };

            Action testCode = () => { resourceRequest.Validate(); };

            var exc = Record.Exception(testCode);

            Assert.NotNull(exc);
        }
    }
}
