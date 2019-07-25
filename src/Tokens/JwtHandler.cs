using Microsoft.IdentityModel.Tokens;
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
        public static JwtSecurityToken CreateToken(SecurityKey securityKey, string issuer, string audience, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256, string x509CertificateSHA1Thumbprint = null)
        {
            return CreateToken(securityKey, issuer, new[] { audience }, claims, issuedAt, beforeIn, expiresIn, algorithm, x509CertificateSHA1Thumbprint);
        }

        /// <summary>
        /// Create and sign JWT token.
        /// </summary>
        public static JwtSecurityToken CreateToken(JsonWebKey jsonWebKey, string issuer, IEnumerable<string> audiences, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256)
        {
            return CreateToken(jsonWebKey as SecurityKey, issuer, audiences , claims, issuedAt, beforeIn, expiresIn, algorithm);
        }

        /// <summary>
        /// Create and sign JWT token.
        /// </summary>
        public static JwtSecurityToken CreateToken(X509Certificate2 certificate, string issuer, IEnumerable<string> audiences, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256)
        {
            return CreateToken(new X509SecurityKey(certificate), issuer, audiences, claims, issuedAt, beforeIn, expiresIn, algorithm);
        }

        /// <summary>
        /// Create and sign JWT token.
        /// </summary>
        public static JwtSecurityToken CreateToken(SecurityKey securityKey, string issuer, IEnumerable<string> audiences, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256, string x509CertificateSHA1Thumbprint = null)
        {
            if (securityKey == null) new ArgumentNullException(nameof(securityKey));
            if (issuer.IsNullOrEmpty()) new ArgumentNullException(nameof(issuer));
            if (audiences?.Count() < 1) throw new ArgumentException($"At least one audience is required.", nameof(audiences));
            if (claims?.Count() < 1) throw new ArgumentException($"At least one claim is required.", nameof(claims));

            var header = new JwtHeader(new SigningCredentials(securityKey, algorithm));
            x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint ?? GetX509CertificateSHA1Thumbprint(securityKey);
            if(!x509CertificateSHA1Thumbprint.IsNullOrEmpty())
            {
                header.Add(IdentityConstants.JwtHeaders.X509CertificateSHA1Thumbprint, x509CertificateSHA1Thumbprint);
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

        /// <summary>
        /// Validate JWT token.
        /// </summary>
        public static (ClaimsPrincipal, SecurityToken) ValidateToken(string token, string issuer, IEnumerable<JsonWebKey> issuerSigningKeys, string audience = null, bool validateAudience = true, bool validateLifetime = true, string nameClaimType = JwtClaimTypes.Subject, string roleClaimType = JwtClaimTypes.Role)
        {
            return ValidateToken(token, issuer, issuerSigningKeys.Select(k => k as SecurityKey), audience, validateAudience, validateLifetime, nameClaimType, roleClaimType);
        }

        /// <summary>
        /// Validate JWT token.
        /// </summary>
        public static (ClaimsPrincipal, SecurityToken) ValidateToken(string token, string issuer, IEnumerable<X509Certificate2> issuerSigningKeys, string audience = null, bool validateAudience = true, bool validateLifetime = true, string nameClaimType = JwtClaimTypes.Subject, string roleClaimType = JwtClaimTypes.Role)
        {
            return ValidateToken(token, issuer, issuerSigningKeys.Select(c => new X509SecurityKey(c)), audience, validateAudience, validateLifetime, nameClaimType, roleClaimType);
        }

        /// <summary>
        /// Validate JWT token.
        /// </summary>
        public static (ClaimsPrincipal, SecurityToken) ValidateToken(string token, string issuer, IEnumerable<SecurityKey> issuerSigningKeys, string audience = null, bool validateAudience = true, bool validateLifetime = true, string nameClaimType = JwtClaimTypes.Subject, string roleClaimType = JwtClaimTypes.Role)
        {
            if (token.IsNullOrEmpty()) new ArgumentNullException(nameof(token));
            if (issuer.IsNullOrEmpty()) new ArgumentNullException(nameof(issuer));
            if (issuerSigningKeys?.Count() < 1) throw new ArgumentException($"At least one key is required.", nameof(issuerSigningKeys));
            if (audience.IsNullOrEmpty()) new ArgumentNullException(nameof(audience));

            var validationParameters = new TokenValidationParameters
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

            SecurityToken securityToken;
            var claimsPrincipal = GetTokenHandler().ValidateToken(token, validationParameters, out securityToken);
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

        private static string GetX509CertificateSHA1Thumbprint(SecurityKey securityKey)
        {
            if (securityKey is JsonWebKey && !(securityKey as JsonWebKey).X5t.IsNullOrEmpty())
            {
                return (securityKey as JsonWebKey).X5t;
            }
            else if (securityKey is X509SecurityKey && !(securityKey as X509SecurityKey).X5t.IsNullOrEmpty())
            {
                return (securityKey as X509SecurityKey).X5t;
            }
            else
            {
                return null;
            }
        }

        private static JwtSecurityTokenHandler GetTokenHandler()
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.InboundClaimTypeMap.Clear();
            return tokenHandler;
        }
    }
}
