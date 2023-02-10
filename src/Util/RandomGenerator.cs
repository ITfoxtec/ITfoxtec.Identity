using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Text;

namespace ITfoxtec.Identity.Util
{
    public static class RandomGenerator
    {
        private static readonly RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();

        public static string GenerateNonce(int length = 32)
        {
            return Generate(length);
        }

        public static string Generate(int length)
        {
            return WebEncoders.Base64UrlEncode(GenerateBytes(length));
        }

        /// <summary>
        /// Generate a simple password which consists of lower and upper case letters (without the letters o and O), numbers (without the number 0) and the special characters '@#%&!'.
        /// The password include at lease 3 of the 4 categories lower case letters, upper case letters, numbers and special characters.
        /// </summary>
        /// <param name="length">Password length, min length 4.</param>
        public static string GenerateSimplePassword(int length)
        {
            if (length < 4) { length = 4; }

            const string lowerCaseLettes = "abcdefghijklmnpqrstuvwxyz";
            const string upperCaseLettes = "ABCDEFGHIJKLMNPQRSTUVWXYZ";
            const string numbers = "123456789";
            const string specialCharacters = "@#%&!";
            var possibleChars = lowerCaseLettes+ upperCaseLettes + numbers + specialCharacters;

            var resultBuilder = new StringBuilder(length);
            resultBuilder.Append(GenerateString(1, lowerCaseLettes));
            resultBuilder.Append(GenerateString(1, upperCaseLettes));
            resultBuilder.Append(GenerateString(1, numbers + specialCharacters));
            resultBuilder.Append(GenerateString(length - 3, possibleChars));
            var result = resultBuilder.ToString().ToCharArray();
            result.Shuffle();
            return new string(result);
        }

        /// <summary>
        /// Generate a code which consists of upper case letters (without the letter O) and numbers (without the number 0).
        /// </summary>
        /// <param name="length">Code length.</param>
        public static string GenerateCode(int length)
        {
            const string upperCaseLettes = "ABCDEFGHIJKLMNPQRSTUVWXYZ";
            const string numbers = "123456789";
            var possibleChars = upperCaseLettes + numbers;
            return GenerateString(length, possibleChars);
        }

        /// <summary>
        /// Generate a code which consists of numbers.
        /// </summary>
        /// <param name="length">Code length.</param>
        public static string GenerateNumberCode(int length)
        {
            const string possibleChars = "0123456789";
            return GenerateString(length, possibleChars);
        }

        public static string GenerateString(int length, string possibleChars)
        {
            var result = new StringBuilder(length);
            for (var position = 0; position < length; position++)
            {
                var index = GenerateNumber(possibleChars.Length);
                result.Append(possibleChars[index]);
            }
            return result.ToString();
        }

        public static byte[] GenerateBytes(int length)
        {
            var bytes = new byte[length];
            randomNumberGenerator.GetNonZeroBytes(bytes);
            return bytes;
        }

        public static int GenerateNumber(int toExclusive)
        {
            return RandomNumberGenerator.GetInt32(toExclusive);
        }


    }
}
