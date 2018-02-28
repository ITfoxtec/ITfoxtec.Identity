using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for JWT.
    /// </summary>
    public static class JwtExtensions
    {
        /// <summary>
        /// Converts a JwtSecurityToken to a JWT string.
        /// </summary>
        public static Task<string> ToJwtString(this JwtSecurityToken jwt)
        {
            var handler = new JwtSecurityTokenHandler();
            return Task.FromResult(handler.WriteToken(jwt));
        }       
    }
}
