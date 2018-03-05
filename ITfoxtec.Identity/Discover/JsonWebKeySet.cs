using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace ITfoxtec.Identity.Discovery
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
        public IEnumerable<JsonWebKey> Keys { get; set; }

        public string ToJson()
        {
            return this.ToJsonIndented();
        }

        public JObject ToJObject()
        {
            return ((object)this).ToJObject();
        }
    }
}
