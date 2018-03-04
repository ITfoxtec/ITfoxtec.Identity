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
            if(values != null)
            {
                return string.Join(" ", values);
            }
            return string.Empty;
        }

        /// <summary>
        /// Converts a string list to a space separated list.
        /// </summary>
        public static string ToSpaceList(this IEnumerable<string> values)
        {
            if (values != null)
            {
                return string.Join(" ", values);
            }
            return string.Empty;
        }

        /// <summary>
        /// Converts a space separated list to a string list.
        /// </summary>
        public static string[] ToSpaceList(this string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                return value.Split(' ');
            }
            return new[] { string.Empty };
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
    }
}
