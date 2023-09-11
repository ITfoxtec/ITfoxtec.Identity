namespace ITfoxtec.Identity
{
    public static class IdentityConstants
    {
        public static class OidcDiscovery
        {
            public const string Path = ".well-known/openid-configuration";
            public const string Keys = "keys";
        }        

        public static class DefaultOidcScopes
        {
            public const string OpenId = "openid";
            public const string Profile = "profile";
            public const string Email = "email";
            public const string Address = "address";
            public const string Phone = "phone";
            public const string OfflineAccess = "offline_access";
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
            public const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
        }
        
        public static class TokenEndpointAuthMethods
        {
            public const string ClientSecretPost = "client_secret_post";
            public const string ClientSecretBasic = "client_secret_basic";
            public const string ClientSecretJwt = "client_secret_jwt";
            public const string PrivateKeyJwt = "private_key_jwt";
        }

        public static class CodeChallengeMethods
        {
            public const string Plain = "plain";
            public const string S256 = "S256";
        }

        public static class TokenTypeIdentifiers
        {
            public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";
            public const string RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";
            public const string IdToken = "urn:ietf:params:oauth:token-type:id_token";
            public const string Saml2 = "urn:ietf:params:oauth:token-type:saml2";
        }

        public static class ClientAuthenticationMethods
        {
            public const string ClientSecretBasic = "client_secret_basic";
            public const string ClientSecretPost = "client_secret_post";
            public const string ClientSecretJwt = "client_secret_jwt";
            public const string PrivateKeyJwt = "private_key_jwt";
        }

        public static class ClientAssertionTypes
        {
            public const string JwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
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
            /// <summary>
            /// The Authorization Server requires End-User interaction of some form to proceed. This error MAY be returned when the prompt parameter value in the Authentication Request is none, 
            /// but the Authentication Request cannot be completed without displaying a user interface for End-User interaction.
            /// </summary>
            public const string InteractionRequired = "interaction_required";
            /// <summary>
            ///  The Authorization Server requires End-User authentication. This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the 
            ///  Authentication Request cannot be completed without displaying a user interface for End-User authentication.
            /// </summary>
            public const string LoginRequired = "login_required";
            /// <summary>
            ///  The End-User is REQUIRED to select a session at the Authorization Server. The End-User MAY be authenticated at the Authorization Server with different associated accounts, 
            ///  but the End-User did not select a session. This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request 
            ///  cannot be completed without displaying a user interface to prompt for a session to use.
            /// </summary>
            public const string AccountSelectionRequired = "account_selection_required";
            /// <summary>
            /// The Authorization Server requires End-User consent.This error MAY be returned when the prompt parameter value in the Authentication Request is none, but the Authentication Request cannot 
            /// be completed without displaying a user interface for End-User consent.
            /// </summary>
            public const string ConsentRequired = "consent_required";
            /// <summary>
            /// The request_uri in the Authorization Request returns an error or contains invalid data.
            /// </summary>
            public const string InvalidRequestUri = "invalid_request_uri";
            /// <summary>
            /// The request parameter contains an invalid Request Object.
            /// </summary>
            public const string InvalidRequestObject = "invalid_request_object";
            /// <summary>
            /// The OP does not support use of the request parameter defined in Section 6.
            /// </summary>
            public const string RequestNotSupported = "request_not_supported";
            /// <summary>
            /// The OP does not support use of the request_uri parameter defined in Section 6.
            /// </summary>
            public const string RequestUriNotSupported = "request_uri_not_supported";
            /// <summary>
            /// The OP does not support use of the registration parameter defined in Section 7.2.1.
            /// </summary>
            public const string RegistrationNotSupported = "registration_not_supported";
            /// <summary>
            /// The access token provided is expired, revoked, malformed, or invalid for other reasons. Bearer Token Usage.
            /// </summary>
            public const string InvalidToken = "invalid_token";
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

        /// <summary>
        /// Default claims.
        /// </summary>
        public static class DefaultJwtClaims
        {
            /// <summary>
            /// Default ID Token claims.
            /// </summary>
            public readonly static string[] IdToken = { JwtClaimTypes.Issuer, JwtClaimTypes.Subject, JwtClaimTypes.SessionId, JwtClaimTypes.Audience, JwtClaimTypes.ExpirationTime, JwtClaimTypes.NotBefore, JwtClaimTypes.IssuedAt, JwtClaimTypes.AuthTime, JwtClaimTypes.Nonce, JwtClaimTypes.Acr, JwtClaimTypes.Amr, JwtClaimTypes.Azp, JwtClaimTypes.AtHash, JwtClaimTypes.CHash };

            /// <summary>
            /// Default Access Token claims.
            /// </summary>
            public readonly static string[] AccessToken = { JwtClaimTypes.Issuer, JwtClaimTypes.Subject, JwtClaimTypes.Audience, JwtClaimTypes.ExpirationTime, JwtClaimTypes.NotBefore, JwtClaimTypes.IssuedAt, JwtClaimTypes.AuthTime, JwtClaimTypes.Amr };
        }

        /// <summary>
        /// Authentication Method Reference values defined by this specification.
        /// </summary>
        public static class AuthenticationMethodReferenceValues
        {
            /// <summary>
            /// Biometric authentication[RFC4949] using facial recognition.
            /// </summary>
            public const string Face = "face";

            /// <summary>
            /// Biometric authentication[RFC4949] using a fingerprint.
            /// </summary>
            public const string Fpt = "fpt";

            /// <summary>
            /// Use of geolocation information for authentication, such as that provided by [W3C.REC-geolocation-API-20161108].
            /// </summary>
            public const string Geo = "geo";

            /// <summary>
            /// Proof-of-Possession(PoP) of a hardware-secured key.See Appendix C of [RFC4211] for a discussion on PoP.
            /// </summary>
            public const string Hwk = "hwk";

            /// <summary>
            /// Biometric authentication [RFC4949] using an iris scan.
            /// </summary>
            public const string Iris = "iris";

            /// <summary>
            /// Knowledge-based authentication [NIST.800-63-2] [ISO29115].
            /// </summary>
            public const string Kba = "kba";

            /// <summary>
            /// Multiple-channel authentication [MCA]. The authentication involves communication over more than one distinct communication channel. For instance, a multiple-channel authentication 
            /// might involve both entering information into a workstation's browser and providing information on a telephone call to a pre-registered number.
            /// </summary>
            public const string Mca = "mca";

            /// <summary>
            /// Multiple-factor authentication [NIST.800-63-2] [ISO29115]. When this is present, specific authentication methods used may also be included.
            /// </summary>
            public const string Mfa = "mfa";

            /// <summary>
            /// One-time password [RFC4949]. One-time password specifications that this authentication method applies to include [RFC4226] and [RFC6238].
            /// </summary>
            public const string Otp = "otp";

            /// <summary>
            ///  Personal Identification Number(PIN) [RFC4949] or pattern (not restricted to containing only numbers) that a user enters to unlock a key on the device. This mechanism should 
            ///  have a way to deter an attacker from obtaining the PIN by trying repeated guesses.
            /// </summary>
            public const string Pin = "pin";

            /// <summary>
            /// Password-based authentication [RFC4949].
            /// </summary>
            public const string Pwd = "pwd";

            /// <summary>
            /// Risk-based authentication [JECM].
            /// </summary>
            public const string rba = "rba";

            /// <summary>
            /// Biometric authentication [RFC4949] using a retina scan.
            /// </summary>
            public const string Retina = "retina";

            /// <summary>
            ///  Smart card [RFC4949].
            /// </summary>
            public const string Sc = "sc";

            /// <summary>
            /// Confirmation using SMS [SMS] text message to the user at a registered number.
            /// </summary>
            public const string Sms = "sms";

            /// <summary>
            /// Proof-of-Possession(PoP) of a software-secured key. See Appendix C of[RFC4211] for a discussion on PoP.
            /// </summary>
            public const string Swk = "swk";

            /// <summary>
            /// Confirmation by telephone call to the user at a registered number. This authentication technique is sometimes also referred to as "call back" [RFC4949].
            /// </summary>
            public const string Tel = "tel";

            /// <summary>
            /// User presence test.Evidence that the end user is present and interacting with the device.This is sometimes also referred to as "test of user presence" [W3C.WD-webauthn-20170216].
            /// </summary>
            public const string User = "user";

            /// <summary>
            /// Biometric authentication[RFC4949] using a voiceprint.
            /// </summary>
            public const string Vbm = "vbm";

            /// <summary>
            /// Windows integrated authentication [MSDN].
            /// </summary>
            public const string Wia = "wia";
        }

        public static class JwtHeaders
        {
            /// <summary>
            /// The "kid" (key ID) header parameter is a hint indicating which specific key owned by the signer should be used to validate the signature. This allows signers to explicitly 
            /// signal a change of key to recipients. Omitting this parameter is equivalent to setting it to an empty string. The interpretation of the contents of the "kid" parameter is 
            /// unspecified. This header parameter is OPTIONAL.
            /// When used with a JWK, the "kid" value is used to match a JWK "kid" parameter value.
            /// </summary>
            public const string Kid = "kid";

            /// <summary>
            /// The "typ" (type) Header Parameter is used by JWT applications to declare the media type of this complete JWT.
            /// </summary>
            public const string Typ = "typ";

            /// <summary>
            /// JWT media types.
            /// </summary>
            public static class MediaTypes
            {
                /// <summary>
                /// JWT media type.
                /// </summary>
                public const string Jwt = "JWT";

                /// <summary>
                /// Access token JWT media type.
                /// </summary>
                public const string AtJwt = "at+JWT";
            }
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

        public static class MessageLength
        {
            public const int ResponseTypeMax = 50;
            public const int ResponseModeMax = 50;
            public const int ClientIdMax = 2000;
            public const int RedirectUriMax = 2000;
            public const int ResourceMax = 500;
            public const int ResourceCountMin = 1;
            public const int ResourceCountMax = 50;
            public const int AudienceMax = 300;
            public const int ScopeMax = 2000;
            public const int StateMax = 2000;
            public const int NonceMax = 2000;
            public const int TokenTypeMax = 50;
            public const int TokenTypeIdentifierMax = 100;
            public const int DisplayMax = 50;
            public const int PromptMax = 50;
            public const int UiLocalesMax = 50;
            public const int LoginHintMax = 2000;
            public const int AcrValuesMax = 1000;
            public const int CodeMax = 4000;
            public const int GrantTypeMax = 100;
            public const int IssuerMax = 200;
            public const int SessionIdMax = 200;
            public const int SessionStatedMax = 200;

            public const int ClientSecretMax = 2000;
            public const int UsernameMax = 500;
            public const int PasswordMax = 2000;

            public const int CodeChallengeMax = 2000;
            public const int CodeChallengeMethodMax = 50;
            public const int CodeVerifierMin = 43;
            public const int CodeVerifierMax = 128;

            public const int AccessTokenMax = 50000;
            public const int IdTokenMax = 50000;
            public const int RefreshTokenMax = 50000;
            public const int AssertionMax = 50000;
            public const int GeneralTokenMax = 50000;
        }
    }
}
