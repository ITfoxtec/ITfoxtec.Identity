using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for arrays and dictionarys.
    /// </summary>
    public static class ListExtensions
    {
        /// <summary>
        /// Converts a string list to a space separated list.
        /// </summary>
        public static string ToSpaceList(this string[] values)
        {
            if(values?.Count() > 0)
            {
                return string.Join(' ', values);
            }
            return null;
        }

        /// <summary>
        /// Converts a string list to a space separated list.
        /// </summary>
        public static string ToSpaceList(this IEnumerable<string> values)
        {
            if (values?.Count() > 0)
            {
                return string.Join(' ', values);
            }
            return null;
        }

        /// <summary>
        /// Converts a space separated list to a string list.
        /// </summary>
        public static string[] ToSpaceList(this string value)
        {
            if (!value.IsNullOrWhiteSpace())
            {
                return value.Split(' ');
            }
            return null;
        }

        /// <summary>
        /// Converts an object to a Dictionary<string, string>.
        /// </summary>
        public static Dictionary<string, string> ToDictionary(this object data)
        {
            var json = data.ToJson();
            return json.ToObject<Dictionary<string, string>>();
        }

        /// <summary>
        /// Converts a Dictionary<string, string> to an object.
        /// </summary>
        public static T ToObject<T>(this Dictionary<string, string> items)
        {
            var json = items.ToJson();
            return json.ToObject<T>();
        }

        /// <summary>
        /// Converts and add an object to a Dictionary<string, string>.
        /// </summary>
        public static Dictionary<string, string> AddToDictionary(this Dictionary<string, string> list, object data)
        {
            var json = data.ToJson();
            return list.Concat(json.ToObject<Dictionary<string, string>>()).ToDictionary(x => x.Key, x => x.Value);
        }

        /// <summary>
        /// Converts a Dictionary<string, string> to a HTML Post page.
        /// </summary>
        public static string ToHtmlPostPage(this Dictionary<string, string> items, string url)
        {
            return string.Concat(HtmlPostPageList(items, url));
        }

        /// <summary>
        /// Converts a Dictionary<string, string> to a HTML Post page.
        /// </summary>
        public static Task<string> ToHtmlPostPageAsync(this Dictionary<string, string> items, string url)
        {
            return Task.FromResult(ToHtmlPostPage(items, url));
        }

        private static IEnumerable<string> HtmlPostPageList(Dictionary<string, string> items, string url)
        {
            yield return
$@"<!DOCTYPE html>
<html lang=""en"">
    <head>
        <meta charset=""utf-8"" />
        <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"">
        <title>OAuth 2.0</title>
    </head>
    <body onload=""document.forms[0].submit()"">
        <noscript>
            <p>
                <strong>Note:</strong> Since your browser does not support JavaScript, 
                you must press the Continue button once to proceed.
            </p>
        </noscript>
        <form action=""{url}"" method=""post"">
            <div>";

            foreach (var item in items)
            {
                yield return
$@"                <input type=""hidden"" name=""{item.Key}"" value=""{WebUtility.HtmlEncode(item.Value)}""/>";
            }

            yield return
$@"            </div>
            <noscript>
                <div>
                    <input type=""submit"" value=""Continue""/>
                </div>
            </noscript>
        </form>
    </body>
</html>";
        }
    }
}
