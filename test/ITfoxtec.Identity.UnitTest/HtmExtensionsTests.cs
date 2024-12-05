using System.Collections.Generic;
using Xunit;

namespace ITfoxtec.Identity.UnitTest
{
    public class HtmExtensionsTests
    {
        [Fact]
        public void AddFragmentTest1()
        {
            var url = "https://test.org/dir/";

            var items = new Dictionary<string, string>
            {
                { "key1", "value1" },
                { "key2", "value2" }
            };

            var resultUrl = url.AddFragment(items);

            Assert.Equal($"{url}#key1=value1&key2=value2", resultUrl);
        }

        [Fact]
        public void AddFragmentTest2()
        {
            var url = "https://test.org/dir?mykey=keyvalue";

            var items = new Dictionary<string, string>
            {
                { "key1", "value1" },
                { "key2", "value2" }
            };

            var resultUrl = url.AddFragment(items);

            Assert.Equal($"{url}#key1=value1&key2=value2", resultUrl);
        }

        [Fact]
        public void AddFragmentTest3()
        {
            var url = "https://test.org/dir#myfragkey=fragkeyvalue";

            var items = new Dictionary<string, string>
            {
                { "key1", "value1" },
                { "key2", "value2" }
            };

            var resultUrl = url.AddFragment(items);

            Assert.Equal($"{url}&key1=value1&key2=value2", resultUrl);
        }

        [Fact]
        public void AddFragmentTest4()
        {
            var url = "https://test.org/dir?mykey=keyvalue#myfragkey=fragkeyvalue";

            var items = new Dictionary<string, string>
            {
                { "key1", "value1" },
                { "key2", "value2" }
            };

            var resultUrl = url.AddFragment(items);

            Assert.Equal($"{url}&key1=value1&key2=value2", resultUrl);
        }

        [Fact]
        public void AddQueryTest1()
        {
            var url = "https://test.org/dir/";

            var items = new Dictionary<string, string>
            {
                { "key1", "value1" },
                { "key2", "value2" }
            };

            var resultUrl = url.AddQuery(items);

            Assert.Equal($"{url}?key1=value1&key2=value2", resultUrl);
        }

        [Fact]
        public void AddQueryTest2()
        {
            var url = "https://test.org/dir?mykey=keyvalue";

            var items = new Dictionary<string, string>
            {
                { "key1", "value1" },
                { "key2", "value2" }
            };

            var resultUrl = url.AddQuery(items);

            Assert.Equal($"{url}&key1=value1&key2=value2", resultUrl);
        }

        [Fact]
        public void AddQueryTest3()
        {
            var url = "https://test.org/dir#myfragkey=fragkeyvalue";

            var items = new Dictionary<string, string>
            {
                { "key1", "value1" },
                { "key2", "value2" }
            };

            var resultUrl = url.AddQuery(items);

            Assert.Equal($"https://test.org/dir?key1=value1&key2=value2#myfragkey=fragkeyvalue", resultUrl);
        }

        [Fact]
        public void AddQueryTest4()
        {
            var url = "https://test.org/dir?mykey=keyvalue#myfragkey=fragkeyvalue";

            var items = new Dictionary<string, string>
            {
                { "key1", "value1" },
                { "key2", "value2" }
            };

            var resultUrl = url.AddQuery(items);

            Assert.Equal($"https://test.org/dir?mykey=keyvalue&key1=value1&key2=value2#myfragkey=fragkeyvalue", resultUrl);
        }
    }
}
