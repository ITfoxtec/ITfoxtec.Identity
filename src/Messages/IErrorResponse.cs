﻿using Newtonsoft.Json;

namespace ITfoxtec.Identity.Messages
{
    public interface IErrorResponse
    {
        /// <summary>
        /// If error REQUIRED. A single ASCII [USASCII] error code.
        /// </summary>
        [JsonProperty(PropertyName = "error")]
        string Error { get; set; }

        /// <summary>
        /// If error OPTIONAL. Human-readable ASCII [USASCII] text providing additional information, used to assist the client developer in understanding the error that occurred.
        /// </summary>
        [JsonProperty(PropertyName = "error_description")]
        string ErrorDescription { get; set; }

        /// <summary>
        /// If error OPTIONAL. A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error.
        /// </summary>
        [JsonProperty(PropertyName = "error_uri")]
        string ErrorUri { get; set; }
    }
}
