using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for Json.
    /// </summary>
    public static class JsonExtensions
    {
        private static readonly JsonSerializer serializer = new JsonSerializer
        {
            NullValueHandling = NullValueHandling.Ignore,
            DefaultValueHandling = DefaultValueHandling.Ignore,
            Formatting = Formatting.Indented
        };

        private static readonly JsonSerializerSettings settings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            DefaultValueHandling = DefaultValueHandling.Ignore,
        };

        private static readonly JsonSerializerSettings settingsIndented = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            DefaultValueHandling = DefaultValueHandling.Ignore,
            Formatting = Formatting.Indented
        };

        /// <summary>
        /// Converts an object to a json object.
        /// </summary>
        public static JObject ToJObject(this object obj)
        {
            return JObject.FromObject(obj, serializer);
        }

        /// <summary>
        /// Converts an object to a json string.
        /// </summary>
        public static string ToJson(this object obj)
        {
            return JsonConvert.SerializeObject(obj, settings);
        }
        /// <summary>
        /// Converts an object to a json indented string.
        /// </summary>
        public static string ToJsonIndented(this object obj)
        {
            return JsonConvert.SerializeObject(obj, settingsIndented);
        }

        /// <summary>
        /// Converts a json string to an object.
        /// </summary>
        public static T ToObject<T>(this string json)
        {
            return JsonConvert.DeserializeObject<T>(json, settings);
        }
    }
}
