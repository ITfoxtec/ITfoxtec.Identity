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

            if (string.IsNullOrEmpty(request.ResponseType)) throw new ArgumentNullException(nameof(request.ResponseType), request.GetTypeName());
            if (string.IsNullOrEmpty(request.ClientId)) throw new ArgumentNullException(nameof(request.ClientId), request.GetTypeName());
            if (string.IsNullOrEmpty(request.RedirectUri)) throw new ArgumentNullException(nameof(request.RedirectUri), request.GetTypeName());
        }

        /// <summary>
        /// Is Valid Oidc Authentication Request.
        /// </summary>
        public static void Validate(this AuthenticationRequest request, bool isImplicitFlow = false)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            (request as AuthorizationRequest).Validate();

            if (string.IsNullOrEmpty(request.Scope)) throw new ArgumentNullException(nameof(request.Scope), request.GetTypeName());
            if (isImplicitFlow && string.IsNullOrEmpty(request.Nonce)) throw new ArgumentNullException(nameof(request.Nonce), request.GetTypeName());        
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Authorization Response.
        /// </summary>
        public static void Validate(this AuthorizationResponse response, bool isImplicitFlow = false)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            if (!string.IsNullOrEmpty(response.Error))
            {
                throw new ResponseErrorException(response.Error, $"{response.GetTypeName()}, {response.ErrorDescription}");
            }

            if (!isImplicitFlow && string.IsNullOrEmpty(response.Code)) throw new ArgumentNullException(nameof(response.Code), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid Oidc Authentication Response.
        /// </summary>
        public static void Validate(this AuthenticationResponse response, bool isImplicitFlow = false)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            (response as AuthorizationResponse).Validate(isImplicitFlow);

            if ((!string.IsNullOrEmpty(response.IdToken) || !string.IsNullOrEmpty(response.AccessToken)) && string.IsNullOrEmpty(response.TokenType))
                throw new ArgumentNullException(nameof(response.TokenType), response.GetTypeName());
            if (isImplicitFlow && string.IsNullOrEmpty(response.IdToken)) throw new ArgumentNullException(nameof(response.IdToken), response.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Access Token Request or OIDC Token Request.
        /// </summary>
        public static void Validate(this TokenRequest request)
        {
            if (request == null) new ArgumentNullException(nameof(request));

            if (string.IsNullOrEmpty(request.GrantType)) throw new ArgumentNullException(nameof(request.GrantType), request.GetTypeName());
        }

        /// <summary>
        /// Is Valid OAuth 2.0 Access Token Response or OIDC Token Response.
        /// </summary>
        public static void Validate(this TokenResponse response, bool isOidc = false)
        {
            if (response == null) new ArgumentNullException(nameof(response));

            if (!string.IsNullOrEmpty(response.Error))
            {
                throw new ResponseErrorException(response.Error, $"{response.GetTypeName()}, {response.ErrorDescription}");
            }

            if (!isOidc && string.IsNullOrEmpty(response.AccessToken)) throw new ArgumentNullException(nameof(response.AccessToken), response.GetTypeName());
            if (string.IsNullOrEmpty(response.TokenType)) throw new ArgumentNullException(nameof(response.TokenType), response.GetTypeName());
            if (isOidc && string.IsNullOrEmpty(response.IdToken)) throw new ArgumentNullException(nameof(response.IdToken), response.GetTypeName());
        }
    }
}
