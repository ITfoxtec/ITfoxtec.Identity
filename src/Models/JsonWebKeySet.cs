using Newtonsoft.Json;
using System.Collections.Generic;

namespace ITfoxtec.Identity.Models
{
    /// <summary>
    /// A JSON Web Key (JWK) set.
    /// </summary>
    public class JsonWebKeySet
    {
        /// <summary>
        /// The value of the "keys" parameter is an array of JWK values. By default, the order of the JWK values within the array does not imply an order of preference among them, although applications 
        /// of JWK Sets can choose to assign a meaning to the order for their purposes, if desired.
        /// </summary>
        [JsonProperty(PropertyName = "keys")]
        public IList<JsonWebKey> Keys { get; set; }
    }
}
