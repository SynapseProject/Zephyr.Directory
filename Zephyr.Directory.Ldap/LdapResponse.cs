using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public class LdapResponse
    {
        [JsonProperty(PropertyName = "searchBase", NullValueHandling = NullValueHandling.Ignore)]
        public string SearchBase { get; set; }

        [JsonProperty(PropertyName = "searchFilter", NullValueHandling = NullValueHandling.Ignore)]
        public string SearchFilter { get; set; }

        [JsonProperty(PropertyName = "records", NullValueHandling = NullValueHandling.Ignore)]
        public List<LdapObject> Records { get; set; } = new List<LdapObject>();
    }
}
