using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public class LdapBatchResponse
    {
        [JsonProperty(PropertyName = "jobID", NullValueHandling = NullValueHandling.Ignore)]
        public string jobID { get; set; }

        [JsonProperty(PropertyName = "recordsID", NullValueHandling = NullValueHandling.Ignore)]
        public string recordsID { get; set; }
    }
}
