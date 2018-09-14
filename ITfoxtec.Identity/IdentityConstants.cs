namespace ITfoxtec.Identity
{
    public static class IdentityConstants
    {
        public static class OidcDiscovery
        {
            public const string Path = ".well-known/openid-configuration";
            public const string Keys = "keys";
        }        

        public static class Endpoints
        {
            public const string Authorization = "authorization";
            public const string Token = "token";
            public const string EndSession = "EndSession";            
        }

        public static class DefaultOidcScopes
        {
            public const string OpenId = "openid";
            public const string Profile = "profile";
            public const string Email = "email";
            public const string Address = "address";
            public const string Phone = "phone";
        }

        public static class ResponseTypes
        {
            public const string Code = "code";
            public const string Token = "token";
            public const string IdToken = "id_token";
        }

        public static class TokenTypes
        {
            public const string Bearer = "Bearer";
        }

        public static class ResponseModes
        {
            public const string Query = "query";
            public const string Fragment = "fragment";
            public const string FormPost = "form_post";
        }

        public static class SubjectTypes
        {
            public const string Pairwise = "pairwise";
            public const string Public = "public";
        }

        public static class GrantTypes
        {
            public const string AuthorizationCode = "authorization_code";
            public const string Password = "password";
            public const string ClientCredentials = "client_credentials";
            public const string RefreshToken = "refresh_token";
            public const string Delegation = "delegation";
        }

        public static class AuthorizationServerDisplay
        {
            /// <summary>
            /// The Authorization Server SHOULD display the authentication and consent UI consistent with a full User Agent page view. If the display parameter is not specified, 
            /// this is the default display mode.
            /// </summary>
            public const string Page = "page";
            /// <summary>
            /// The Authorization Server SHOULD display the authentication and consent UI consistent with a popup User Agent window. The popup User Agent window should be of an 
            /// appropriate size for a login-focused dialog and should not obscure the entire window that it is popping up over.
            /// </summary>
            public const string Popup = "popup";
            /// <summary>
            /// The Authorization Server SHOULD display the authentication and consent UI consistent with a device that leverages a touch interface.
            /// </summary>
            public const string Touch = "touch";
            /// <summary>
            /// The Authorization Server SHOULD display the authentication and consent UI consistent with a "feature phone" type display.
            /// </summary>
            public const string Wap = "wap";
        }

        public static class AuthorizationServerPrompt
        {
            /// <summary>
            /// The Authorization Server MUST NOT display any authentication or consent user interface pages. 
            /// </summary>
            public const string None = "none";
            /// <summary>
            /// The Authorization Server SHOULD prompt the End-User for reauthentication.
            /// </summary>
            public const string Login = "login";
            /// <summary>
            /// The Authorization Server SHOULD prompt the End-User for consent before returning information to the Client.
            /// </summary>
            public const string Consent = "consent";
            /// <summary>
            /// The Authorization Server SHOULD prompt the End-User to select a user account.
            /// </summary>
            public const string SelectAccount = "select_account";
        }

        public static class ResponseErrors
        {
            /// <summary>
            /// The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.
            /// </summary>
            public const string InvalidRequest = "invalid_request";
            /// <summary>
            /// Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).
            /// </summary>
            public const string InvalidClient = "invalid_client";
            /// <summary>
            /// The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used 
            /// in the authorization request, or was issued to another client.
            /// </summary>
            public const string InvalidGrant = "invalid_grant";
            /// <summary>
            /// The client is not authorized to request an authorization code using this method.
            /// </summary>
            public const string UnauthorizedClient = "unauthorized_client";
            /// <summary>
            /// The resource owner or authorization server denied the request.
            /// </summary>
            public const string AccessDenied = "access_denied";
            /// <summary>
            /// The authorization server does not support obtaining an authorization code using this method.
            /// </summary>
            public const string UnsupportedResponseType = "unsupported_response_type";
            /// <summary>
            /// The authorization grant type is not supported by the authorization server.
            /// </summary>
            public const string UnsupportedGrantType = "unsupported_grant_type";
            /// <summary>
            /// The requested scope is invalid, unknown, or malformed.
            /// </summary>
            public const string InvalidScope = "invalid_scope";
            /// <summary>
            /// The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
            /// </summary>
            public const string ServerError = "server_error";
            /// <summary>
            ///  The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.
            /// </summary>
            public const string TemporarilyUnavailable = "temporarily_unavailable";
        }

        public static class Algorithms
        {
            /// <summary>
            /// No digital signature or MAC performed
            /// </summary>
            public const string None = "none";

            public static class Symmetric
            {
                /// <summary>
                /// HMAC using SHA-256
                /// </summary>
                public const string HS256 = "HS256";
                /// <summary>
                /// HMAC using SHA-384
                /// </summary>
                public const string HS384 = "HS284";
                /// <summary>
                /// HMAC using SHA-512
                /// </summary>
                public const string HS512 = "HS512";
            }

            public static class Asymmetric
            {
                /// <summary>
                /// RSASSA PKCS1 v1.5 using SHA-256
                /// </summary>
                public const string RS256 = "RS256";
                /// <summary>
                /// RSASSA PKCS1 v1.5 using SHA-384
                /// </summary>
                public const string RS384 = "RS384";
                /// <summary>
                /// RSASSA PKCS1 v1.5 using SHA-512
                /// </summary>
                public const string RS512 = "RS512";

                /// <summary>
                /// ECDSA using P-256 and SHA-256
                /// </summary>
                public const string ES256 = "ES256";
                /// <summary>
                /// ECDSA using P-256 and SHA-384
                /// </summary>
                public const string ES384 = "ES384";
                /// <summary>
                /// ECDSA using P-256 and SHA-512
                /// </summary>
                public const string ES512 = "ES512";

                /// <summary>
                /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256   
                /// </summary>
                public const string PS256 = "PS256";
                /// <summary>
                /// RSASSA-PSS using SHA-256 and MGF1 with SHA-384   
                /// </summary>
                public const string PS384 = "PS384";
                /// <summary>
                /// RSASSA-PSS using SHA-256 and MGF1 with SHA-512   
                /// </summary>
                public const string PS512 = "PS512";
            }
        }

        public static class JwtHeaders
        {
            public const string X509CertificateSHA1Thumbprint = "x5t";
        }

        public static class JsonWebKeyTypes
        {
            /// <summary>
            /// Elliptic Curve [Digital Signature Standard (DSS)]
            /// </summary>
            public const string EC = "EC";
            /// <summary>
            /// RSA [RFC3447]   
            /// </summary>
            public const string RSA = "RSA";
            /// <summary>
            /// Octet sequence (used to represent symmetric keys)
            /// </summary>
            public const string Oct = "oct";
        }

        public static class JsonPublicKeyUse
        {
            public const string Signature = "sig";
            public const string Encryption = "enc";
        }

        public static class JsonKeyOperations
        {
            /// <summary>
            /// Compute digital signature or MAC
            /// </summary>
            public const string Sign = "sign";
            /// <summary>
            /// Verify digital signature or MAC
            /// </summary>
            public const string Verify = "verify";
            /// <summary>
            /// Encrypt content
            /// </summary>
            public const string Encrypt = "encrypt";
            /// <summary>
            /// Decrypt content and validate decryption, if applicable
            /// </summary>
            public const string Decrypt = "decrypt";
            /// <summary>
            /// Encrypt key
            /// </summary>
            public const string WrapKey = "wrapKey";
            /// <summary>
            /// Decrypt key and validate decryption, if applicable
            /// </summary>
            public const string UnwrapKey = "unwrapKey";
            /// <summary>
            /// Derive key
            /// </summary>
            public const string DeriveKey = "deriveKey";
            /// <summary>
            /// Derive bits not to be used as a key
            /// </summary>
            public const string DeriveBits = "deriveBits";
        }
    }
}
