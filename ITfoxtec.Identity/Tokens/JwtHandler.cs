using Microsoft.AspNetCore.WebUtilities;
using msTokens = Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using msJwt = System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Discovery;

namespace ITfoxtec.Identity.Tokens
{
    public class JwtHandler
    {
        public static msJwt.JwtSecurityToken CreateToken(JsonWebKey jwk, string issuer, string audience, IEnumerable<Claim> claims, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256)
        {
            var header = new msJwt.JwtHeader(new msTokens.SigningCredentials(ConvertJsonWebKey(jwk), algorithm));
            if (!string.IsNullOrEmpty(jwk.X509CertificateSHA1Thumbprint))
            {
                header.Add(IdentityConstants.JwtHeaders.X509CertificateSHA1Thumbprint, jwk.X509CertificateSHA1Thumbprint);
            }

            var udtNow = DateTime.UtcNow;
            var payload = new msJwt.JwtPayload(issuer, audience, claims, udtNow.AddMinutes(-beforeIn), udtNow.AddSeconds(expiresIn));

            return new msJwt.JwtSecurityToken(header, payload);
        }

        public static msJwt.JwtSecurityToken CreateToken(X509Certificate2 certificate, string issuer, string audience, IEnumerable<Claim> claims, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256)
        {   
            var header = new msJwt.JwtHeader(new msTokens.SigningCredentials(new msTokens.X509SecurityKey(certificate), algorithm));
            header.Add(IdentityConstants.JwtHeaders.X509CertificateSHA1Thumbprint, WebEncoders.Base64UrlEncode(certificate.GetCertHash()));

            var udtNow = DateTime.UtcNow;
            var payload = new msJwt.JwtPayload(issuer, audience, claims, udtNow.AddMinutes(-beforeIn), udtNow.AddSeconds(expiresIn));

            return new msJwt.JwtSecurityToken(header, payload);
        }

        public static (ClaimsPrincipal, msTokens.SecurityToken) ValidateToken(string token, string issuer, IEnumerable<JsonWebKey> issuerSigningKeys, string audience = null, bool validateAudience = true, string nameClaimType = JwtClaimTypes.Subject, string rolesClaimType = JwtClaimTypes.Roles)
        {
            var validationParameters = new msTokens.TokenValidationParameters
            {
                SaveSigninToken = true,
                ValidIssuer = issuer,
                IssuerSigningKeys = ConvertJsonWebKeys(issuerSigningKeys),
                ValidateAudience = validateAudience,
                ValidAudience = audience,
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
