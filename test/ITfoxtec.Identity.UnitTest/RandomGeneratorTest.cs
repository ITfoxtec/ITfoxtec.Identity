using ITfoxtec.Identity.Util;
using System.Linq;
using Xunit;

namespace ITfoxtec.Identity.UnitTest
{
    public class RandomGeneratorTest
    {           
        [Fact]
        public void Generate6Test()
        {
            var result = RandomGenerator.Generate(6);

            Assert.True(result.Count() >= 6);
        }

        [Fact]
        public void GenerateCodeTest()
        {
            var result = RandomGenerator.GenerateCode(6);

            Assert.True(result.Count() == 6);
        }

        [Fact]
        public void GenerateNumberCodeTest()
        {
            var result = RandomGenerator.GenerateNumberCode(6);

            Assert.True(result.Count() == 6);
        }

        [Fact]
        public void GenerateSimplePasswordTest()
        {
            var result = RandomGenerator.GenerateSimplePassword(10);

            Assert.True(result.Count() == 10);
        }
    }
}
