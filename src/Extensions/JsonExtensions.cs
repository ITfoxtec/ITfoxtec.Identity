using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for Json.
    /// </summary>
    public static class JsonExtensions
    {
        /// <summary>
        /// JsonSerializer with indented format.
        /// </summary>
        public static readonly JsonSerializer SerializerIndented = new JsonSerializer
        {
            NullValueHandling = NullValueHandling.Ignore,
            DefaultValueHandling = DefaultValueHandling.Ignore,
            Formatting = Formatting.Indented
        };

        /// <summary>
        /// JsonSerializerSettings.
        /// </summary>
        public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            DefaultValueHandling = DefaultValueHandling.Ignore,
        };

        /// <summary>
        /// JsonSerializerSettings with indented format.
        /// </summary>
        public static readonly JsonSerializerSettings SettingsIndented = new JsonSerializerSettings
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
            return JObject.FromObject(obj, SerializerIndented);
        }

        /// <summary>
        /// Converts an object to a json string.
        /// </summary>
        public static string ToJson(this object obj)
        {
            return JsonConvert.SerializeObject(obj, Settings);
        }
        /// <summary>
        /// Converts an object to a json indented string.
        /// </summary>
        public static string ToJsonIndented(this object obj)
        {
            return JsonConvert.SerializeObject(obj, SettingsIndented);
        }

        /// <summary>
        /// Converts a json string to an object.
        /// </summary>
        public static T ToObject<T>(this string json)
        {
            return JsonConvert.DeserializeObject<T>(json, Settings);
        }
    }
}
