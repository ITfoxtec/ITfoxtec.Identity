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
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Access Token Request or OIDC Token Request.
        /// </summary>
        public static void Validate(this TokenRequest request)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            if (request.GrantType.IsNullOrEmpty()) throw new ArgumentNullException(nameof(request.GrantType), request.GetTypeName());
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
        }
    }
}
