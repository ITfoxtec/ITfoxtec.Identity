﻿using MSTokens = Microsoft.IdentityModel.Tokens;
using ITfoxtec.Identity.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Tokens
{
    /// <summary>
    /// Jwt handler.
    /// </summary>
    public class JwtHandler
    {
        /// <summary>
        /// Create and sign JWT token.
        /// </summary>
        public static JwtSecurityToken CreateToken(MSTokens.SecurityKey securityKey, string issuer, string audience, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, 
            string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256, string typ = IdentityConstants.JwtHeaders.MediaTypes.Jwt)
        {
            return CreateToken(securityKey, issuer, new[] { audience }, claims, issuedAt: issuedAt, beforeIn: beforeIn, expiresIn: expiresIn, algorithm: algorithm, typ: typ);
        }

        /// <summary>
        /// Create and sign JWT token.
        /// </summary>
        public static JwtSecurityToken CreateToken(JsonWebKey jsonWebKey, string issuer, IEnumerable<string> audiences, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600,
            string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256, string typ = IdentityConstants.JwtHeaders.MediaTypes.Jwt)
        {
            return CreateToken(jsonWebKey.ToSecurityKey(), issuer, audiences , claims, issuedAt: issuedAt, beforeIn: beforeIn, expiresIn: expiresIn, algorithm: algorithm, typ: typ);
        }

        /// <summary>
        /// Create and sign JWT token.
        /// </summary>
        public static JwtSecurityToken CreateToken(X509Certificate2 certificate, string issuer, IEnumerable<string> audiences, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, 
            string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256, string typ = IdentityConstants.JwtHeaders.MediaTypes.Jwt)
        {
            return CreateToken(new MSTokens.X509SecurityKey(certificate), issuer, audiences, claims, issuedAt: issuedAt, beforeIn: beforeIn, expiresIn: expiresIn, algorithm: algorithm, typ: typ);
        }

        /// <summary>
        /// Create and sign JWT token.
        /// </summary>
        public static JwtSecurityToken CreateToken(MSTokens.SecurityKey securityKey, string issuer, IEnumerable<string> audiences, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600,
            string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256, string typ = IdentityConstants.JwtHeaders.MediaTypes.Jwt)
        {
            if (securityKey == null) new ArgumentNullException(nameof(securityKey));
            if (issuer.IsNullOrEmpty()) new ArgumentNullException(nameof(issuer));
            if (audiences?.Count() < 1) throw new ArgumentException($"At least one audience is required.", nameof(audiences));
            if (claims?.Count() < 1) throw new ArgumentException($"At least one claim is required.", nameof(claims));

            var key = securityKey is MSTokens.JsonWebKey jsonWebKey ? jsonWebKey.ToSecurityKey() : securityKey;
            var header = new JwtHeader(new MSTokens.SigningCredentials(key, algorithm));
            if (!typ.IsNullOrEmpty())
            {
                header[IdentityConstants.JwtHeaders.Typ] = typ;
            }

            if (!issuedAt.HasValue)
            {
                issuedAt = DateTimeOffset.UtcNow;
            }
            var payload = new JwtPayload(issuer, audiences.First(), claims, issuedAt.Value.AddSeconds(-beforeIn).UtcDateTime, issuedAt.Value.AddSeconds(expiresIn).UtcDateTime, issuedAt.Value.UtcDateTime);
            if (audiences.Count() > 1)
            {
                foreach (var audience in audiences.Skip(1))
                {
                    payload.AddClaim(new Claim(JwtClaimTypes.Audience, audience));
                } 
            }
            return new JwtSecurityToken(header, payload);
        }

        // .NET 5.0 error, System.Security.Cryptography.RSA.Create() - System.PlatformNotSupportedException: System.Security.Cryptography.Algorithms is not supported on this platform.
        // https://github.com/dotnet/aspnetcore/issues/26123
        // https://github.com/dotnet/runtime/issues/40074

        /// <summary>
        /// Validate JWT token.
        /// </summary>
        public static (ClaimsPrincipal, MSTokens.SecurityToken) ValidateToken(string token, string issuer, IEnumerable<JsonWebKey> issuerSigningKeys, string audience = null, bool validateAudience = true, bool validateLifetime = true,
            string nameClaimType = JwtClaimTypes.Subject, string roleClaimType = JwtClaimTypes.Role
#if NET50
            , bool validateSigningKey = true
#endif
            )
        {
            return ValidateToken(token, issuer, issuerSigningKeys.ToMSJsonWebKeys(), audience: audience, validateAudience: validateAudience, validateLifetime: validateLifetime, nameClaimType: nameClaimType, roleClaimType: roleClaimType
#if NET50
                , validateSigningKey: validateSigningKey
#endif
                );
        }

        /// <summary>
        /// Validate JWT token.
        /// </summary>
        public static (ClaimsPrincipal, MSTokens.SecurityToken) ValidateToken(string token, string issuer, IEnumerable<X509Certificate2> issuerSigningKeys, string audience = null, bool validateAudience = true, bool validateLifetime = true,
            string nameClaimType = JwtClaimTypes.Subject, string roleClaimType = JwtClaimTypes.Role
#if NET50
            , bool validateSigningKey = true
#endif
            )
        {
            return ValidateToken(token, issuer, issuerSigningKeys.Select(c => new MSTokens.X509SecurityKey(c)), audience: audience, validateAudience: validateAudience, validateLifetime: validateLifetime, nameClaimType: nameClaimType, roleClaimType: roleClaimType
#if NET50
                , validateSigningKey: validateSigningKey
#endif
                );
        }

        /// <summary>
        /// Validate JWT token.
        /// </summary>
        public static (ClaimsPrincipal, MSTokens.SecurityToken) ValidateToken(string token, string issuer, IEnumerable<MSTokens.SecurityKey> issuerSigningKeys, string audience = null, bool validateAudience = true, bool validateLifetime = true,
            string nameClaimType = JwtClaimTypes.Subject, string roleClaimType = JwtClaimTypes.Role
#if NET50
            , bool validateSigningKey = true
#endif
            )
        {
            if (token.IsNullOrEmpty()) new ArgumentNullException(nameof(token));
            if (issuer.IsNullOrEmpty()) new ArgumentNullException(nameof(issuer));
            if (issuerSigningKeys?.Count() < 1) throw new ArgumentException($"At least one key is required.", nameof(issuerSigningKeys));
            if (audience.IsNullOrEmpty()) new ArgumentNullException(nameof(audience));

            var validationParameters = new MSTokens.TokenValidationParameters
            {
                SaveSigninToken = true,
                ValidIssuer = issuer,
                IssuerSigningKeys = issuerSigningKeys,
                ValidAudience = audience,
                ValidateAudience = validateAudience,
                ValidateLifetime = validateLifetime,
                NameClaimType = nameClaimType,
                RoleClaimType = roleClaimType,
            };

            MSTokens.SecurityToken securityToken = null;
            ClaimsPrincipal claimsPrincipal = null;

#if NET50
            if (!validateSigningKey) 
            {
                var jwtSecurityToken = GetTokenHandler().ReadJwtToken(token);
                claimsPrincipal = new ClaimsPrincipal(
                    new ClaimsIdentity(jwtSecurityToken.Claims, "AuthenticationTypes.Federation", JwtClaimTypes.Subject, JwtClaimTypes.Role)
                    { 
                        BootstrapContext = token 
                    });
            }
            else 
            {
#endif
            claimsPrincipal = GetTokenHandler().ValidateToken(token, validationParameters, out securityToken);
#if NET50
            }
#endif


            return (claimsPrincipal, securityToken);
        }

        /// <summary>
        /// Read JWT token.
        /// </summary>
        public static JwtSecurityToken ReadToken(string token)
        {
            if (token.IsNullOrEmpty()) new ArgumentNullException(nameof(token));

            return GetTokenHandler().ReadJwtToken(token);
        }

        private static JwtSecurityTokenHandler GetTokenHandler()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.InboundClaimTypeMap.Clear();
            return tokenHandler;
        }
    }
}
