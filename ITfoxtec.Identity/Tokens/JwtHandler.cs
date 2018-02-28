using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Tokens
{
    public class JwtHandler
    {
        public static JwtSecurityToken CreateToken(X509Certificate2 certificate, string issuer, string audience, IEnumerable<Claim> claims, int beforeIn = 60, int expiresIn = 3600, string algorithm = IdentityConstants.Algorithms.Asymmetric.RS256)
        {   
            var header = new JwtHeader(new SigningCredentials(new X509SecurityKey(certificate), algorithm));
            header.Add(IdentityConstants.JwtHeaders.X509CertificateSHA1Thumbprint, WebEncoders.Base64UrlEncode(certificate.GetCertHash()));

            var udtNow = DateTime.UtcNow;
            var payload = new JwtPayload(issuer, audience, claims, udtNow.AddMinutes(-beforeIn), udtNow.AddSeconds(expiresIn));

            return new JwtSecurityToken(header, payload);
        }
    }
}
