using ITfoxtec.Identity.Messages;
using System;
using Xunit;

namespace ITfoxtec.Identity.UnitTest
{
    public class StateValidationTests
    {
        [Theory]
        [InlineData(2000)]
        [InlineData(2029)]
        [InlineData(4000)]
        public void AuthenticationRequestAcceptsStateWithinLimit(int length)
        {
            var state = new string('s', length);
            var request = CreateAuthenticationRequest(state);

            request.Validate(isImplicitFlow: true);

            Assert.Equal(state, request.ToDictionary()["state"]);
        }

        [Theory]
        [InlineData(2000)]
        [InlineData(2029)]
        [InlineData(4000)]
        public void AuthenticationResponseAcceptsStateWithinLimit(int length)
        {
            var state = new string('s', length);
            var response = new AuthenticationResponse { IdToken = "id-token", State = state };

            response.Validate(isImplicitFlow: true);

            Assert.Equal(state, response.ToDictionary()["state"]);
        }

        [Theory]
        [InlineData(2000)]
        [InlineData(2029)]
        [InlineData(4000)]
        public void LogoutRequestAndResponseAcceptStateWithinLimit(int length)
        {
            var state = new string('s', length);
            var request = new RpInitiatedLogoutRequest { State = state };
            var response = new RpInitiatedLogoutResponse { State = state };

            request.Validate();
            response.Validate();

            Assert.Equal(state, request.ToDictionary()["state"]);
            Assert.Equal(state, response.ToDictionary()["state"]);
        }

        [Fact]
        public void AuthenticationRequestRejectsStateAboveLimit()
        {
            var request = CreateAuthenticationRequest(new string('s', 4001));

            var exception = Assert.Throws<ArgumentException>(() => request.Validate(isImplicitFlow: true));

            Assert.Equal("State at AuthenticationRequest", exception.ParamName);
        }

        [Fact]
        public void AuthenticationResponseRejectsStateAboveLimit()
        {
            var response = new AuthenticationResponse { IdToken = "id-token", State = new string('s', 4001) };

            var exception = Assert.Throws<ArgumentException>(() => response.Validate(isImplicitFlow: true));

            Assert.Equal("State at AuthenticationResponse", exception.ParamName);
        }

        [Fact]
        public void LogoutRequestAndResponseRejectStateAboveLimit()
        {
            var state = new string('s', 4001);
            var request = new RpInitiatedLogoutRequest { State = state };
            var response = new RpInitiatedLogoutResponse { State = state };

            var requestException = Assert.Throws<ArgumentException>(() => request.Validate());
            var responseException = Assert.Throws<ArgumentException>(() => response.Validate());

            Assert.Equal("State at RpInitiatedLogoutRequest", requestException.ParamName);
            Assert.Equal("State at RpInitiatedLogoutResponse", responseException.ParamName);
        }

        private static AuthenticationRequest CreateAuthenticationRequest(string state)
        {
            return new AuthenticationRequest
            {
                ClientId = "client",
                RedirectUri = "https://client.example/callback",
                ResponseType = IdentityConstants.ResponseTypes.IdToken,
                ResponseMode = IdentityConstants.ResponseModes.FormPost,
                Scope = IdentityConstants.DefaultOidcScopes.OpenId,
                Nonce = "nonce",
                State = state
            };
        }
    }
}
