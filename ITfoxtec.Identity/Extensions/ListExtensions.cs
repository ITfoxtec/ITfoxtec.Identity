using System.Collections.Generic;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for arrays and directorys.
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
        /// Converts a string list to a space separated  list.
        /// </summary>
        public static Dictionary<string, string> ToDirectory(this object data)
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
    }
}
