using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;

namespace ITfoxtec.Identity.Util
{
    public static class RandomGenerator
    {
        private static readonly RandomNumberGenerator randomNonceGenerator = RandomNumberGenerator.Create();

        public static string GenerateNonce(int length = 32)
        {
            var bytes = new byte[length];
            randomNonceGenerator.GetNonZeroBytes(bytes);
            return WebEncoders.Base64UrlEncode(bytes);
        }
    }
}
