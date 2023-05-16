using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
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

        [JsonProperty(PropertyName = "totalRecords", NullValueHandling = NullValueHandling.Ignore)]
        public int TotalRecords { get; set; } = 0;

        [JsonProperty(PropertyName = "message", NullValueHandling = NullValueHandling.Ignore)]
        public string Message { get; set; }

        [JsonProperty(PropertyName = "resultsIncomplete", NullValueHandling = NullValueHandling.Ignore)]
        public bool? ResultsIncomplete { get; set; }

        [JsonProperty(PropertyName = "records", NullValueHandling = NullValueHandling.Ignore)]
        public List<LdapObject> Records { get; set; }
    }
}
