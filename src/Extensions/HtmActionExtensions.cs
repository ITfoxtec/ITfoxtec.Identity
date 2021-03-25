using Microsoft.AspNetCore.WebUtilities;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for HTML form and redirect actions.
    /// </summary>
    public static class HtmActionExtensions
    {
        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action post page.
        /// </summary>
        public static string ToHtmlPostPage(this Dictionary<string, string> items, string url, string title = "OAuth 2.0")
        {
            return string.Concat(items.HtmFormActionPageList(url, "post", title: title));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action post page.
        /// </summary>
        public static Task<string> ToHtmlPostPageAsync(this Dictionary<string, string> items, string url, string title = "OAuth 2.0")
        {
            return Task.FromResult(ToHtmlPostPage(items, url, title: title));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action get page.
        /// </summary>
        public static string ToHtmlGetPage(this Dictionary<string, string> items, string url, string title = "OAuth 2.0")
        {
            return string.Concat(items.HtmFormActionPageList(url, "get", title: title));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action get page.
        /// </summary>
        public static Task<string> ToHtmlGetPageAsync(this Dictionary<string, string> items, string url, string title = "OAuth 2.0")
        {
            return Task.FromResult(ToHtmlGetPage(items, url, title: title));
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action fragment page.
        /// </summary>
        public static string ToHtmlFragmentPage(this Dictionary<string, string> items, string url, string title = "OAuth 2.0")
        {
            var redirectUrl = QueryHelpers.AddQueryString(url, items).Replace('?', '#');
            return redirectUrl.HtmRedirectActionPage(title: title);
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to a HTML form action fragment page.
        /// </summary>
        public static Task<string> ToHtmlFragmentPageAsync(this Dictionary<string, string> items, string url, string title = "OAuth 2.0")
        {
            return Task.FromResult(ToHtmlFragmentPage(items, url, title: title));
        }

        public static IEnumerable<string> HtmFormActionPageList(this Dictionary<string, string> items, string url, string method, string title = "OAuth 2.0")
        {
            yield return
$@"<!DOCTYPE html>
<html lang=""en"">
    <head>
        <meta charset=""utf-8"" />
        <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"" />
        <title>{title}</title>
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

        public static string HtmRedirectActionPage(this string url, string title = "OAuth 2.0")
        {
            return
$@"<!DOCTYPE html>
<html lang=""en"">
    <head>
        <meta charset=""utf-8"" />
        <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"" />
        <meta http-equiv=""refresh"" content=""0;URL='{url}'"" />
        <title>{title}</title>
    </head>
    <body>
    </body>
</html>";
        }
    }
}
