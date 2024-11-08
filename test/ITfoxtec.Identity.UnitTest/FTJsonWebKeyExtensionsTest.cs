using ITfoxtec.Identity.Models;
using Xunit;
using System;
using System.Linq;

namespace ITfoxtec.Identity.UnitTest
{
    public class FTJsonWebKeyExtensionsTest
    {
        #region RsaKey
        private static string rsaKey =
@"{
    ""kty"": ""RSA"",
    ""use"": ""sig"",
    ""kid"": ""VMSIKa0T0RJABxANt0mDMerZazg"",
    ""n"": ""rDPv-9TBO9-Ut7QCYKEEdLejH1biK-e6HiMz8t09tB9RjnpMHMUTSh8tV0pU2Dcdc_mO1-V0baH2R4ypmgjZDewGDhskbSGt_Vm8TcRWavw1zyLMiYiJ2ZZXVazMBck6MtURtN_EOCXaTUzuFRYkOY91TvMqOsYAf7hc6kyTVeRIbqY8U2DJ-1efwuVcugu1vLP5UYeM5oRMpNyTFPeDHcPqadexAEwsN1PhUuEKkq5EsIPNGrWS0wkv5h2MXkxuZOy95lNq05HA5FAR-UMINy3jOmy3BLwN_oY3HMfJndKK-Jmbfu8avIWlf-owZykhwNEEpfrltusbaS6p7UABlQ"",
    ""e"": ""AQAB""
}";

        [Fact]
        public void GetPublicKeyRsaKeyTest()
        {
            var key = rsaKey.ToObject<JsonWebKey>();
            var privateKey = key.GetPublicKey();

            Assert.Equal(key.Kid, privateKey.Kid);
        }

        [Fact]
        public void ToRsaParametersRsaKeyTest()
        {
            var key = rsaKey.ToObject<JsonWebKey>();
            var rsaParameters = key.ToRsaParameters();
        }

        [Fact]
        public void ToSecurityKeyRsaKeyTest()
        {
            var key = rsaKey.ToObject<JsonWebKey>();
            var securityKey = key.ToSecurityKey();

            Assert.Equal(key.Kid, securityKey.KeyId);
        }

        [Fact]
        public void ToMSJsonWebKeyRsaKeyTest()
        {
            var key = rsaKey.ToObject<JsonWebKey>();
            var msKey = key.ToMSJsonWebKey();

            Assert.Equal(key.Kid, msKey.Kid);
        }

        [Fact]
        public void ToMSJsonWebKeysRsaKeyTest()
        {
            var keys = new[] { rsaKey.ToObject<JsonWebKey>() };
            var msKeys = keys.ToMSJsonWebKeys().ToArray();

            for (var i = 0; i < keys.Length; i++)
            {
                Assert.Equal(keys[i].Kid, msKeys[i].Kid);
            }
        }

        [Fact]
        public void HasPrivateKeyRsaKeyTest()
        {
            var key = rsaKey.ToObject<JsonWebKey>();
            var hasPrivateKey = key.HasPrivateKey();

            Assert.False(hasPrivateKey);
        }

        [Fact]
        public void ToX509CertificateRsaKeyTest()
        {
            var key = rsaKey.ToObject<JsonWebKey>();
            Assert.Throws<ArgumentNullException>(() => key.ToX509Certificate());
        }
        #endregion

        #region EllipticCurveKey
        private static string ecKey =
@"{
    ""kty"": ""EC"",
    ""use"": ""sig"",
    ""crv"": ""P-256"",
    ""kid"": ""VMSIKa0T0RJABxANt0mDMerZazg"",
    ""x"": ""klJ78rPJUieUqJw4V3LeOVYGjvBToNVw3i-lHrRFeYo"",
    ""y"": ""p742Tb1ONYstDhSY0K9yX2VnlhLJCjIr3sLJDFEQl9c""
}";

        [Fact]
        public void GetPublicKeyEcKeyTest()
        {
            var key = ecKey.ToObject<JsonWebKey>();
            var privateKey = key.GetPublicKey();

            Assert.Equal(key.Kid, privateKey.Kid);
        }

        [Fact]
        public void ToMSJsonWebKeyEcKeyTest()
        {
            var key = ecKey.ToObject<JsonWebKey>();
            var msKey = key.ToMSJsonWebKey();

            Assert.Equal(key.Kid, msKey.Kid);
        }

        [Fact]
        public void ToMSJsonWebKeysEcKeyTest()
        {
            var keys = new[] { ecKey.ToObject<JsonWebKey>() };
            var msKeys = keys.ToMSJsonWebKeys().ToArray();

            for (var i = 0; i < keys.Length; i++)
            {
                Assert.Equal(keys[i].Kid, msKeys[i].Kid);
            }
        }

        [Fact]
        public void HasPrivateKeyEcKeyTest()
        {
            var key = ecKey.ToObject<JsonWebKey>();
            var hasPrivateKey = key.HasPrivateKey();

            Assert.False(hasPrivateKey);
        }
        #endregion
    }
}
