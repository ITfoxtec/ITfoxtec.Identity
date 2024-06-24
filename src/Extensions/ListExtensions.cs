using ITfoxtec.Identity.Messages;
using ITfoxtec.Identity.Util;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Linq;

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
                return string.Join(" ", values);
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
                return string.Join(" ", values);
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
        /// Converts a IEnumerable&lt;KeyValuePair&lt;string, StringValues&gt;&gt; to a Dictionary&lt;string, string&gt;.
        /// </summary>
        public static Dictionary<string, string> ToDictionary(this IEnumerable<KeyValuePair<string, StringValues>> items)
        {
            return items.ToDictionary(x => x.Key, x => x.Value.FirstOrDefault());
        }

        /// <summary>
        /// Get authorization header bearer token from a IEnumerable&lt;KeyValuePair&lt;string, StringValues&gt;&gt;.
        /// </summary>
        public static string GetAuthorizationHeaderBearer(this IEnumerable<KeyValuePair<string, StringValues>> items)
        {
            return items.GetAuthorizationHeader(IdentityConstants.TokenTypes.Bearer);
        }

        /// <summary>
        /// Get authorization header client credential basic from a IEnumerable&lt;KeyValuePair&lt;string, StringValues&gt;&gt;.
        /// </summary>
        public static (string clientId, string clientSecret) GetAuthorizationHeaderBasic(this IEnumerable<KeyValuePair<string, StringValues>> items)
        {
            var value = items.GetAuthorizationHeader(IdentityConstants.BasicAuthentication.Basic);
            if (!value.IsNullOrEmpty())
            {
                var valueSplit = value.Base64Decode()?.Split(':');
                if (valueSplit?.Count() == 2)
                {
                    return (valueSplit[0].OAuthUrlDencode(), valueSplit[1].OAuthUrlDencode());
                }
            }
            return (null, null);
        }

        /// <summary>
        /// Get authorization header from a IEnumerable&lt;KeyValuePair&lt;string, StringValues&gt;&gt;.
        /// </summary>
        public static string GetAuthorizationHeader(this IEnumerable<KeyValuePair<string, StringValues>> items, string scheme)
        {
            var bearerHeader = items.Where(h => h.Key.Equals(HeaderNames.Authorization, StringComparison.Ordinal)).Select(h => h.Value.FirstOrDefault()).FirstOrDefault();
            if (bearerHeader?.StartsWith($"{scheme} ", StringComparison.Ordinal) == true)
            {
                return bearerHeader.Substring(scheme.Length + 1);
            }
            return null;
        }

        /// <summary>
        /// Converts a Dictionary&lt;string, string&gt; to an object.
        /// </summary>
        public static T ToObject<T>(this Dictionary<string, string> items)
        {
            var json = items.ToJson();
            return json.ToObject<T>();
        }

        /// <summary>
        /// Converts a IEnumerable&lt;KeyValuePair&lt;string, StringValues&gt;&gt; to an object.
        /// </summary>
        public static T ToObject<T>(this IEnumerable<KeyValuePair<string, StringValues>> items)
        {
            var json = items.ToDictionary().ToJson();
            return json.ToObject<T>();
        }

        /// <summary>
        /// Converts and add an object to a Dictionary&lt;string, string&gt;.
        /// </summary>
        public static Dictionary<string, string> AddToDictionary(this Dictionary<string, string> list, object data)
        {
            var json = data.ToJson();
            return list.Concat(json.ToObject<Dictionary<string, string>>()).ToDictionary(x => x.Key, x => x.Value);
        }

        /// <summary>
        /// Converts and add an ResourceRequest object to a Dictionary&lt;string, string&gt;.
        /// </summary>
        public static Dictionary<string, string> AddToDictionary(this Dictionary<string, string> list, ResourceRequest resourceRequest)
        {
            if(resourceRequest?.Resources?.Count() > 0)
            {
                if(resourceRequest.Resources.Count() > 1)
                {
                    throw new NotSupportedException("Currently only one resource parameter is supported.");
                }
                var resourceJsonName = resourceRequest.GetJsonPropertyName(nameof(ResourceRequest.Resources));
                foreach (var resource in resourceRequest.Resources)
                {
                    list.Add(resourceJsonName, resource);
                }
            }
            return list;
        }

#if !NETSTANDARD
        public static void Shuffle<T>(this IList<T> list)
        {
            if (list == null) throw new ArgumentNullException(nameof(list));
            int n = list.Count;
            while (n > 1)
            {
                int k = RandomGenerator.GenerateNumber(n--);
                (list[n], list[k]) = (list[k], list[n]);
            }
        }
#endif
    }
}
