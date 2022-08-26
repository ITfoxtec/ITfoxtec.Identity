using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using System;
using System.Linq;

namespace ITfoxtec.Identity
{
    /// <summary>
    /// Extension methods for JSON.
    /// </summary>
    public static class JsonExtensions
    {
        private static readonly IContractResolver defaultResolver = JsonSerializer.CreateDefault().ContractResolver;

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
        /// Converts an object to a JSON object.
        /// </summary>
        public static JObject ToJObject(this object obj)
        {
            return JObject.FromObject(obj, SerializerIndented);
        }

        /// <summary>
        /// Converts an object to a JSON string.
        /// </summary>
        public static string ToJson(this object obj)
        {
            return JsonConvert.SerializeObject(obj, Settings);
        }
        /// <summary>
        /// Converts an object to a JSON indented string.
        /// </summary>
        public static string ToJsonIndented(this object obj)
        {
            return JsonConvert.SerializeObject(obj, SettingsIndented);
        }

        /// <summary>
        /// Converts a JSON string to an object.
        /// </summary>
        public static T ToObject<T>(this string json)
        {
            return JsonConvert.DeserializeObject<T>(json, Settings);
        }

        public static string GetJsonPropertyName(this object obj, string propertyName)
        {
            if (obj == null) throw new ArgumentNullException(nameof(obj));

            var contract = defaultResolver.ResolveContract(obj.GetType()) as JsonObjectContract;
            if (contract == null)
            {
                throw new ArgumentException($"'{obj.GetType().Name}' is not serialized as a JSON object");
            }

            var property = contract.Properties.Where(p => p.UnderlyingName.Equals(propertyName, StringComparison.Ordinal)).FirstOrDefault();
            if (property == null)
            {
                throw new ArgumentException($"Property {propertyName} was not found.");
            }
            return property.PropertyName;
        }
    }
}
