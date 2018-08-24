using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;

namespace ITfoxtec.Identity.Util
{
    public static class RandomGenerator
    {
        private static readonly RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();

        public static string Generate(int length)
        {
            var bytes = new byte[length];
            randomNumberGenerator.GetNonZeroBytes(bytes);
            return WebEncoders.Base64UrlEncode(bytes);
        }

        public static string GenerateNonce(int length = 32)
        {
            return Generate(length);
        }
    }
}
