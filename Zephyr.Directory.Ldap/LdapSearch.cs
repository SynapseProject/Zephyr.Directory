using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public class LdapSearch
    {
        [JsonProperty(PropertyName = "base", NullValueHandling = NullValueHandling.Ignore)]
        public string Base { get; set; }

        [JsonProperty(PropertyName = "filter", NullValueHandling = NullValueHandling.Ignore)]
        public string Filter { get; set; }

        [JsonProperty(PropertyName = "attributes", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Attributes { get; set; }

    }
}
