using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public enum StatusCode
    {
        Success,
        Failure,
        SuccessWithErrors
    }

    public class LdapResponse
    {
        [JsonProperty(PropertyName = "success", NullValueHandling = NullValueHandling.Ignore)]
        public bool Success { get; set; } = true;

        [JsonProperty(PropertyName = "server", NullValueHandling = NullValueHandling.Ignore)]
        public string Server { get; set; }

        [JsonProperty(PropertyName = "searchBase", NullValueHandling = NullValueHandling.Ignore)]
        public string SearchBase { get; set; }

        [JsonProperty(PropertyName = "searchFilter", NullValueHandling = NullValueHandling.Ignore)]
        public string SearchFilter { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(PropertyName = "status", NullValueHandling = NullValueHandling.Ignore)]
        public StatusCode Status { get; set; }

        [JsonProperty(PropertyName = "message", NullValueHandling = NullValueHandling.Ignore)]
        public string Message { get; set; }

        [JsonProperty(PropertyName = "totalRecords", NullValueHandling = NullValueHandling.Ignore)]
        public int? TotalRecords { get; set; }

        [JsonProperty(PropertyName = "nextToken", NullValueHandling = NullValueHandling.Ignore)]
        public string NextToken { get; set; }

        [JsonProperty(PropertyName = "records", NullValueHandling = NullValueHandling.Ignore)]
        public List<LdapObject> Records { get; set; }

    }
}
