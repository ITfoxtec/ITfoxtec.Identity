using Microsoft.AspNetCore.WebUtilities;
using System.Collections.Generic;
using System.Net;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for HTML form, redirect actions and iframe.
    /// </summary>
    public static class HtmExtensions
    {
        /// <summary>
        /// Converts URL and Dictionary&lt;string, string&gt; to a HTML form action post page.
        /// </summary>
        public static string ToHtmlPostPage(this string url, Dictionary<string, string> items)
        {
            return string.Concat(url.HtmFormActionPageList(items));
        }

        /// <summary>
        /// Converts URL and Dictionary&lt;string, string&gt; to a HTML form action page.
        /// </summary>
        private static IEnumerable<string> HtmFormActionPageList(this string url, Dictionary<string, string> items)
        {
            yield return
$@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""utf-8"" />
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
</head>
<body>
    <noscript>
        <p>
            <strong>Note:</strong> Since your browser does not support JavaScript, 
            you must press the Continue button once to proceed.
        </p>
    </noscript>
    <form action=""{url}"" method=""post"">
        <div>
";

        if (items?.Count > 0)
        {
            foreach (var item in items)
            {
                yield return
$@"            <input type=""hidden"" name=""{item.Key}"" value=""{WebUtility.HtmlEncode(item.Value)}""/>
";
            }
        }

        yield return
$@"        </div>
        <noscript>
            <div>
                <input type=""submit"" value=""Continue""/>
            </div>
        </noscript>
    </form>
</body>
<script>window.addEventListener(""DOMContentLoaded"", function() {{ document.forms[0].submit() }})</script>
</html>";
        }

        /// <summary>
        /// Add query Dictionary&lt;string, string&gt; to URL.
        /// </summary>
        public static string AddQuery(this string url, Dictionary<string, string> items)
        {
            var urlWithQuery = QueryHelpers.AddQueryString(url, items);
            return urlWithQuery;
        }

        /// <summary>
        /// Add fragment Dictionary&lt;string, string&gt; to URL.
        /// </summary>
        public static string AddFragment(this string url, Dictionary<string, string> items)
        {
            url = url.Replace('?', '¤');
            url = url.Replace('#', '?');
            var urlWithFragment = QueryHelpers.AddQueryString(url, items).Replace('?', '#');
            return urlWithFragment.Replace('¤' , '?');
        }

        /// <summary>
        /// Converts URLs to a HTML iframe and redirect page.
        /// </summary>
        public static string ToHtmIframePage(this List<string> urls, string redirectUrl, string title = "OAuth 2.0")
        {
            return string.Concat(urls.ToHtmIframePageList(redirectUrl, title: title));
        }

        /// <summary>
        /// URLs to a HTML iframe and redirect page.
        /// </summary>
        private static IEnumerable<string> ToHtmIframePageList(this List<string> urls, string redirectUrl, string title = "OAuth 2.0")
        {
            yield return
@"<!DOCTYPE html>
<html lang=""en"">
    <head>
        <meta charset=""utf-8"" />
        <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"" />
";
            if (!redirectUrl.IsNullOrEmpty()) 
            { 
                yield return
$@"        <meta http-equiv=""refresh"" content=""0;URL='{redirectUrl}'"" />
";
            }

            yield return
$@"        <title>{title}</title>
    </head>
    <body>
        <div>
";
            if (urls?.Count > 0)
            {
                foreach (var url in urls)
                {
                    yield return
$@"            <iframe width=""0"" height=""0"" frameborder=""0"" src=""{url}""></iframe>
";
                }
            }

            yield return
$@"        </div>
    </body>
</html>";
        }
    }
}