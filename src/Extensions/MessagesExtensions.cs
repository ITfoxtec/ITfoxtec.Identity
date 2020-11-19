using ITfoxtec.Identity.Messages;
using System;
using System.Linq;

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

            request.ResponseType.ValidateMaxLength(IdentityConstants.MessageLength.ResponseTypeMax, nameof(request.ResponseType), request.GetTypeName());
            request.ClientId.ValidateMaxLength(IdentityConstants.MessageLength.ClientIdMax, nameof(request.ClientId), request.GetTypeName());
            request.RedirectUri.ValidateMaxLength(IdentityConstants.MessageLength.RedirectUriMax, nameof(request.RedirectUri), request.GetTypeName());
            request.Scope.ValidateMaxLength(IdentityConstants.MessageLength.ScopeMax, nameof(request.Scope), request.GetTypeName());
            request.State.ValidateMaxLength(IdentityConstants.MessageLength.StateMax, nameof(request.State), request.GetTypeName());
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

            request.ResponseMode.ValidateMaxLength(IdentityConstants.MessageLength.ResponseModeMax, nameof(request.ResponseMode), request.GetTypeName());
            request.Nonce.ValidateMaxLength(IdentityConstants.MessageLength.NonceMax, nameof(request.Nonce), request.GetTypeName());
            request.Display.ValidateMaxLength(IdentityConstants.MessageLength.DisplayMax, nameof(request.Display), request.GetTypeName());
            request.Prompt.ValidateMaxLength(IdentityConstants.MessageLength.PromptMax, nameof(request.Prompt), request.GetTypeName());
            request.UiLocales.ValidateMaxLength(IdentityConstants.MessageLength.UiLocalesMax, nameof(request.UiLocales), request.GetTypeName());
            request.IdTokenHint.ValidateMaxLength(IdentityConstants.MessageLength.IdTokenMax, nameof(request.IdTokenHint), request.GetTypeName());
            request.LoginHint.ValidateMaxLength(IdentityConstants.MessageLength.LoginHintMax, nameof(request.LoginHint), request.GetTypeName());
            request.AcrValues.ValidateMaxLength(IdentityConstants.MessageLength.AcrValuesMax, nameof(request.AcrValues), request.GetTypeName());
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

            response.Code.ValidateMaxLength(IdentityConstants.MessageLength.CodeMax, nameof(response.Code), response.GetTypeName());
            response.State.ValidateMaxLength(IdentityConstants.MessageLength.StateMax, nameof(response.State), response.GetTypeName());
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

            response.IdToken.ValidateMaxLength(IdentityConstants.MessageLength.IdTokenMax, nameof(response.IdToken), response.GetTypeName());
            response.AccessToken .ValidateMaxLength(IdentityConstants.MessageLength.AccessTokenMax, nameof(response.AccessToken), response.GetTypeName());
            response.TokenType.ValidateMaxLength(IdentityConstants.MessageLength.TokenTypeMax, nameof(response.TokenType), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Access Token Request or OIDC Token Request.
        /// </summary>
        public static void Validate(this TokenRequest request)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            if (request.GrantType.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.GrantType), request.GetTypeName());

            if (request.GrantType == IdentityConstants.GrantTypes.AuthorizationCode)
            {
                if (request.Code.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.Code), request.GetTypeName());
            }
            else if (request.GrantType == IdentityConstants.GrantTypes.RefreshToken)
            {
                if (request.RefreshToken.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.RefreshToken), request.GetTypeName());
            }
            else if (request.GrantType == IdentityConstants.GrantTypes.ClientCredentials)
            {
                if (request.ClientId.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.ClientId), request.GetTypeName());
            }
            else if (request.GrantType == IdentityConstants.GrantTypes.Delegation)
            {
                if (request.Assertion.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.Assertion), request.GetTypeName());
            }

            request.GrantType.ValidateMaxLength(IdentityConstants.MessageLength.GrantTypeMax, nameof(request.GrantType), request.GetTypeName());
            request.Code.ValidateMaxLength(IdentityConstants.MessageLength.CodeMax, nameof(request.Code), request.GetTypeName());
            request.RefreshToken.ValidateMaxLength(IdentityConstants.MessageLength.RefreshTokenMax, nameof(request.RefreshToken), request.GetTypeName());
            request.Assertion.ValidateMaxLength(IdentityConstants.MessageLength.AssertionMax, nameof(request.Assertion), request.GetTypeName());
            request.RedirectUri.ValidateMaxLength(IdentityConstants.MessageLength.RedirectUriMax, nameof(request.RedirectUri), request.GetTypeName());
            request.ClientId.ValidateMaxLength(IdentityConstants.MessageLength.ClientIdMax, nameof(request.ClientId), request.GetTypeName());
            request.Scope.ValidateMaxLength(IdentityConstants.MessageLength.ScopeMax, nameof(request.Scope), request.GetTypeName());
            request.Username.ValidateMaxLength(IdentityConstants.MessageLength.UsernameMax, nameof(request.Username), request.GetTypeName());
            request.Password.ValidateMaxLength(IdentityConstants.MessageLength.PasswordMax, nameof(request.Password), request.GetTypeName());
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

            response.IdToken.ValidateMaxLength(IdentityConstants.MessageLength.IdTokenMax, nameof(response.IdToken), response.GetTypeName());
            response.AccessToken.ValidateMaxLength(IdentityConstants.MessageLength.AccessTokenMax, nameof(response.AccessToken), response.GetTypeName());
            response.TokenType.ValidateMaxLength(IdentityConstants.MessageLength.TokenTypeMax, nameof(response.TokenType), response.GetTypeName());
            response.RefreshToken.ValidateMaxLength(IdentityConstants.MessageLength.RefreshTokenMax, nameof(response.RefreshToken), response.GetTypeName());
            response.Scope.ValidateMaxLength(IdentityConstants.MessageLength.ScopeMax, nameof(response.Scope), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 client credentials.
        /// </summary>
        public static void Validate(this ClientCredentials clientCredentials)
        {
            if (clientCredentials == null) new ArgumentNullException(nameof(clientCredentials));

            if (clientCredentials.ClientSecret.IsNullOrEmpty()) throw new ArgumentNullException(nameof(clientCredentials.ClientSecret), clientCredentials.GetTypeName());

            clientCredentials.ClientSecret.ValidateMaxLength(IdentityConstants.MessageLength.ClientSecretMax, nameof(clientCredentials.ClientSecret), clientCredentials.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Code Challenge Secret.
        /// </summary>
        public static void Validate(this CodeChallengeSecret codeChallengeSecret)
        {
            if (codeChallengeSecret == null) new ArgumentNullException(nameof(codeChallengeSecret));

            if (codeChallengeSecret.CodeChallenge.IsNullOrEmpty()) throw new ArgumentNullException(nameof(codeChallengeSecret.CodeChallenge), codeChallengeSecret.GetTypeName());

            codeChallengeSecret.CodeChallenge.ValidateMaxLength(IdentityConstants.MessageLength.CodeChallengeMax, nameof(codeChallengeSecret.CodeChallenge), codeChallengeSecret.GetTypeName());
            codeChallengeSecret.CodeChallengeMethod.ValidateMaxLength(IdentityConstants.MessageLength.CodeChallengeMethodMax, nameof(codeChallengeSecret.CodeChallengeMethod), codeChallengeSecret.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Code Verifier Secret.
        /// </summary>
        public static void Validate(this CodeVerifierSecret codeVerifierSecret)
        {
            if (codeVerifierSecret == null) new ArgumentNullException(nameof(codeVerifierSecret));

            if (codeVerifierSecret.CodeVerifier.IsNullOrEmpty()) throw new ArgumentNullException(nameof(codeVerifierSecret.CodeVerifier), codeVerifierSecret.GetTypeName());

            codeVerifierSecret.CodeVerifier.ValidateMinLength(IdentityConstants.MessageLength.CodeVerifierMin, nameof(codeVerifierSecret.CodeVerifier), codeVerifierSecret.GetTypeName());
            codeVerifierSecret.CodeVerifier.ValidateMaxLength(IdentityConstants.MessageLength.CodeVerifierMax, nameof(codeVerifierSecret.CodeVerifier), codeVerifierSecret.GetTypeName());
        }

        /// <summary>
        /// Is Valid OIDC Session Response.
        /// </summary>
        public static void Validate(this SessionResponse response)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            response.SessionState.ValidateMaxLength(IdentityConstants.MessageLength.SessionStatedMax, nameof(response.SessionState), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid OIDC End Session Request.
        /// </summary>
        public static void Validate(this EndSessionRequest request)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            request.IdTokenHint.ValidateMaxLength(IdentityConstants.MessageLength.IdTokenMax, nameof(request.IdTokenHint), request.GetTypeName());
            request.PostLogoutRedirectUri.ValidateMaxLength(IdentityConstants.MessageLength.RedirectUriMax, nameof(request.PostLogoutRedirectUri), request.GetTypeName());
            request.State.ValidateMaxLength(IdentityConstants.MessageLength.StateMax, nameof(request.State), request.GetTypeName());
        }

        /// <summary>
        /// Is Valid OIDC End Session Response.
        /// </summary>
        public static void Validate(this EndSessionResponse response)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            response.State.ValidateMaxLength(IdentityConstants.MessageLength.StateMax, nameof(response.State), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid Resource Indicators for OAuth 2.0 request.
        /// </summary>
        public static void Validate(this ResourceRequest request)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            request.Resources.ValidateMinListLength(IdentityConstants.MessageLength.ResourceCountMin, nameof(request.Resources), request.GetTypeName());
            request.Resources.ValidateMaxListLength(IdentityConstants.MessageLength.ResourceCountMax, nameof(request.Resources), request.GetTypeName());

            var count = 1;
            foreach(var resource in request.Resources)
            {
                if (resource.IsNullOrEmpty()) throw new ArgumentNullException($"{nameof(request.Resources)}[{count}]", request.GetTypeName());
                resource.ValidateMaxLength(IdentityConstants.MessageLength.ResourceMax, $"{nameof(request.Resources)}[{count}]", request.GetTypeName());
                count++;
            }

            
        }
    }
}
