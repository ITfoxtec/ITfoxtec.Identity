using Microsoft.AspNetCore.WebUtilities;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for HTML form actions.
    /// </summary>
    public static class HtmFormActionExtensions
    {
        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action post page.
        /// </summary>
        public static string ToHtmlPostPage(this Dictionary<string, string> items, string url)
        {
            return string.Concat(HtmFormActionPageList(items, url, "post"));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action post page.
        /// </summary>
        public static Task<string> ToHtmlPostPageAsync(this Dictionary<string, string> items, string url)
        {
            return Task.FromResult(ToHtmlPostPage(items, url));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action get page.
        /// </summary>
        public static string ToHtmlGetPage(this Dictionary<string, string> items, string url)
        {
            return string.Concat(HtmFormActionPageList(items, url, "get"));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action get page.
        /// </summary>
        public static Task<string> ToHtmlGetPageAsync(this Dictionary<string, string> items, string url)
        {
            return Task.FromResult(ToHtmlGetPage(items, url));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action fragment page.
        /// </summary>
        public static string ToHtmlFragmentPage(this Dictionary<string, string> items, string url)
        {
            var formUrl = QueryHelpers.AddQueryString(url, items).Replace('?', '#');
            return string.Concat(HtmFormActionPageList(null, formUrl, "get"));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action fragment page.
        /// </summary>
        public static Task<string> ToHtmlFragmentPageAsync(this Dictionary<string, string> items, string url)
        {
            return Task.FromResult(ToHtmlFragmentPage(items, url));
        }

        private static IEnumerable<string> HtmFormActionPageList(Dictionary<string, string> items, string url, string method)
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
        <form action=""{url}"" method=""{method}"">
            <div>
";

            if (items?.Count > 0)
            {
                foreach (var item in items)
                {
                    yield return
    $@"                <input type=""hidden"" name=""{item.Key}"" value=""{WebUtility.HtmlEncode(item.Value)}""/>
";
                }
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
