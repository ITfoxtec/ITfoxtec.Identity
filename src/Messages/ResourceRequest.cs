using Newtonsoft.Json;
using System.Collections.Generic;

namespace ITfoxtec.Identity.Messages
{
    /// <summary>
    /// Resource Indicators for OAuth 2.0
    /// </summary>
    public class ResourceRequest
    {
        /// <summary>
        /// Indicates the target service or resource to which access is being requested. Its value MUST be an absolute URI, as specified by Section 4.3 of[RFC3986]. 
        /// The URI MUST NOT include a fragment component. It SHOULD NOT include a query component, unless the query component a useful and necessary part of 
        /// the resource parameter.
        /// Multiple "resource" parameters MAY be used to indicate that the requested token is intended to be used at multiple resources.
        /// </summary>
        [JsonProperty(PropertyName = "resource")]
        public IEnumerable<string> Resources { get; set; }
    }
}
