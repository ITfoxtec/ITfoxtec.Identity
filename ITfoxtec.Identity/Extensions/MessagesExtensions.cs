using ITfoxtec.Identity.Messages;
using System;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for Messages.
    /// </summary>
    public static class MessagesExtensions
    {
        /// <summary>
        /// Is Valid OAuth 2.0 Authorization Request.
        /// </summary>
        public static void Validate(this AuthorizationRequest request)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            if (request.ResponseType.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.ResponseType), request.GetTypeName());
            if (request.ClientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.ClientId), request.GetTypeName());
            if (request.RedirectUri.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.RedirectUri), request.GetTypeName());

            request.ResponseType.ValidateMaxLength(32, nameof(request.ResponseType), request.GetTypeName());
            request.ClientId.ValidateMaxLength(128, nameof(request.ClientId), request.GetTypeName());
            request.RedirectUri.ValidateMaxLength(512, nameof(request.RedirectUri), request.GetTypeName());
            request.Scope.ValidateMaxLength(128, nameof(request.Scope), request.GetTypeName());
            request.State.ValidateMaxLength(512, nameof(request.State), request.GetTypeName());
        }

        /// <summary>
        /// Is Valid Oidc Authentication Request.
        /// </summary>
        public static void Validate(this AuthenticationRequest request, bool isImplicitFlow = false)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            (request as AuthorizationRequest).Validate();

            if (request.Scope.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.Scope), request.GetTypeName());
            if (isImplicitFlow && request.Nonce.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.Nonce), request.GetTypeName());

            request.ResponseMode.ValidateMaxLength(32, nameof(request.ResponseMode), request.GetTypeName());
            request.Nonce.ValidateMaxLength(512, nameof(request.Nonce), request.GetTypeName());
            request.Display.ValidateMaxLength(32, nameof(request.Display), request.GetTypeName());
            request.Prompt.ValidateMaxLength(32, nameof(request.Prompt), request.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Authorization Response.
        /// </summary>
        public static void Validate(this AuthorizationResponse response, bool isImplicitFlow = false)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            if (!response.Error.IsNullOrEmpty())
            {
                throw new ResponseErrorException(response.Error, $"{response.GetTypeName()}, {response.ErrorDescription}");
            }

            if (!isImplicitFlow && response.Code.IsNullOrEmpty()) throw new ArgumentNullException(nameof(response.Code), response.GetTypeName());

            response.Code.ValidateMaxLength(512, nameof(response.Code), response.GetTypeName());
            response.State.ValidateMaxLength(512, nameof(response.State), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid Oidc Authentication Response.
        /// </summary>
        public static void Validate(this AuthenticationResponse response, bool isImplicitFlow = false)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            (response as AuthorizationResponse).Validate(isImplicitFlow);

            if ((!response.IdToken.IsNullOrEmpty() || !response.AccessToken.IsNullOrEmpty()) && response.TokenType.IsNullOrEmpty())
                throw new ArgumentNullException(nameof(response.TokenType), response.GetTypeName());
            if (isImplicitFlow && response.IdToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(response.IdToken), response.GetTypeName());

            response.IdToken.ValidateMaxLength(5120, nameof(response.IdToken), response.GetTypeName());
            response.AccessToken .ValidateMaxLength(5120, nameof(response.AccessToken), response.GetTypeName());
            response.TokenType.ValidateMaxLength(32, nameof(response.TokenType), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Access Token Request or OIDC Token Request.
        /// </summary>
        public static void Validate(this TokenRequest request)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            if (request.GrantType.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.GrantType), request.GetTypeName());

            request.GrantType.ValidateMaxLength(32, nameof(request.GrantType), request.GetTypeName());
            request.Code.ValidateMaxLength(512, nameof(request.Code), request.GetTypeName());
            request.Assertion.ValidateMaxLength(5120, nameof(request.Assertion), request.GetTypeName());
            request.RedirectUri.ValidateMaxLength(512, nameof(request.RedirectUri), request.GetTypeName());
            request.ClientId.ValidateMaxLength(128, nameof(request.ClientId), request.GetTypeName());
            request.Scope.ValidateMaxLength(128, nameof(request.Scope), request.GetTypeName());
            request.Username.ValidateMaxLength(128, nameof(request.Username), request.GetTypeName());
            request.Password.ValidateMaxLength(128, nameof(request.Password), request.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Access Token Response or OIDC Token Response.
        /// </summary>
        public static void Validate(this TokenResponse response, bool isOidc = false)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            if (!response.Error.IsNullOrEmpty())
            {
                throw new ResponseErrorException(response.Error, $"{response.GetTypeName()}, {response.ErrorDescription}");
            }

            if (!isOidc && response.AccessToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(response.AccessToken), response.GetTypeName());
            if (response.TokenType.IsNullOrEmpty()) throw new ArgumentNullException(nameof(response.TokenType), response.GetTypeName());
            if (isOidc && response.IdToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(response.IdToken), response.GetTypeName());

            response.IdToken.ValidateMaxLength(5120, nameof(response.IdToken), response.GetTypeName());
            response.AccessToken.ValidateMaxLength(5120, nameof(response.AccessToken), response.GetTypeName());
            response.TokenType.ValidateMaxLength(32, nameof(response.TokenType), response.GetTypeName());
            response.RefreshToken.ValidateMaxLength(512, nameof(response.RefreshToken), response.GetTypeName());
            response.Scope.ValidateMaxLength(128, nameof(response.Scope), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid OIDC Session Response.
        /// </summary>
        public static void Validate(this SessionResponse response)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            response.SessionState.ValidateMaxLength(512, nameof(response.SessionState), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid OIDC End Session Request.
        /// </summary>
        public static void Validate(this EndSessionRequest request)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            request.IdTokenHint.ValidateMaxLength(5120, nameof(request.IdTokenHint), request.GetTypeName());
            request.PostLogoutRedirectUri.ValidateMaxLength(512, nameof(request.PostLogoutRedirectUri), request.GetTypeName());
            request.State.ValidateMaxLength(512, nameof(request.State), request.GetTypeName());
        }

        /// <summary>
        /// Is Valid OIDC End Session Response.
        /// </summary>
        public static void Validate(this EndSessionResponse response)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            response.State.ValidateMaxLength(512, nameof(response.State), response.GetTypeName());
        }
    }
}
