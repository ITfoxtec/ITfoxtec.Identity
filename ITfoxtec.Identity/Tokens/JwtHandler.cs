using Microsoft.AspNetCore.WebUtilities;
using msTokens = Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using msJwt = System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Discovery;
using System.Linq;

namespace ITfoxtec.Identity.Tokens
{
    public class JwtHandler
    {
        public static msJwt.JwtSecurityToken CreateToken(JsonWebKey jwk, string issuer, string audiences, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256)
        {
            return CreateToken(jwk, issuer, new[] { audiences }, claims, issuedAt, beforeIn, expiresIn, algorithm);
        }
        public static msJwt.JwtSecurityToken CreateToken(JsonWebKey jwk, string issuer, IEnumerable<string> audiences, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256)
        {
            if (audiences?.Count() < 1) throw new ArgumentException($"At least one audience is required.", "audience");

            var header = new msJwt.JwtHeader(new msTokens.SigningCredentials(ConvertJsonWebKey(jwk), algorithm));
            if (!jwk.X509CertificateSHA1Thumbprint.IsNullOrEmpty())
            {
                header.Add(IdentityConstants.JwtHeaders.X509CertificateSHA1Thumbprint, jwk.X509CertificateSHA1Thumbprint);
            }

            if(!issuedAt.HasValue)
            {
                issuedAt = DateTimeOffset.UtcNow;
            }
            var payload = new msJwt.JwtPayload(issuer, audiences.First(), claims, issuedAt.Value.AddSeconds(-beforeIn).UtcDateTime, issuedAt.Value.AddSeconds(expiresIn).UtcDateTime, issuedAt.Value.UtcDateTime);
            if (audiences.Count() > 1)
            {
                foreach (var audience in audiences.Skip(1))
                {
                    payload.AddClaim(new Claim(JwtClaimTypes.Audience, audience));
                } 
            }
            return new msJwt.JwtSecurityToken(header, payload);
        }

        public static msJwt.JwtSecurityToken CreateToken(X509Certificate2 certificate, string issuer, string audience, IEnumerable<Claim> claims, DateTimeOffset? issuedAt = null, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256)
        {   
            var header = new msJwt.JwtHeader(new msTokens.SigningCredentials(new msTokens.X509SecurityKey(certificate), algorithm));
            header.Add(IdentityConstants.JwtHeaders.X509CertificateSHA1Thumbprint, WebEncoders.Base64UrlEncode(certificate.GetCertHash()));

            if (!issuedAt.HasValue)
            {
                issuedAt = DateTimeOffset.UtcNow;
            }
            var payload = new msJwt.JwtPayload(issuer, audience, claims, issuedAt.Value.AddSeconds(-beforeIn).UtcDateTime, issuedAt.Value.AddSeconds(expiresIn).UtcDateTime, issuedAt.Value.UtcDateTime);

            return new msJwt.JwtSecurityToken(header, payload);
        }

        public static (ClaimsPrincipal, msTokens.SecurityToken) ValidateToken(string token, string issuer, IEnumerable<JsonWebKey> issuerSigningKeys, string audience = null, bool validateAudience = true, bool validateLifetime = true, string nameClaimType = JwtClaimTypes.Subject, string rolesClaimType = JwtClaimTypes.Roles)
        {
            var validationParameters = new msTokens.TokenValidationParameters
            {
                SaveSigninToken = true,
                ValidIssuer = issuer,
                IssuerSigningKeys = ConvertJsonWebKeys(issuerSigningKeys),
                ValidAudience = audience,
                ValidateAudience = validateAudience,
                ValidateLifetime = validateLifetime,
                NameClaimType = nameClaimType,
                RoleClaimType = rolesClaimType,
            };

            msTokens.SecurityToken securityToken;
            var claimsPrincipal = GetTokenHandler().ValidateToken(token, validationParameters, out securityToken);
            return (claimsPrincipal, securityToken);
        }

        public static msJwt.JwtSecurityToken ReadToken(string token)
        {
            return GetTokenHandler().ReadJwtToken(token);
        }

        private static msJwt.JwtSecurityTokenHandler GetTokenHandler()
        {
            var tokenHandler = new msJwt.JwtSecurityTokenHandler();
            tokenHandler.InboundClaimTypeMap.Clear();
            return tokenHandler;
        }

        private static msTokens.JsonWebKey ConvertJsonWebKey(JsonWebKey jwk)
        {
            var json = jwk.ToJson();
            return json.ToObject<msTokens.JsonWebKey>();
        }

        private static IEnumerable<msTokens.JsonWebKey> ConvertJsonWebKeys(IEnumerable<JsonWebKey> jwks)
        {          
            var json = jwks.ToJson();
            return json.ToObject<IEnumerable<msTokens.JsonWebKey>>();
        }
    }
}
