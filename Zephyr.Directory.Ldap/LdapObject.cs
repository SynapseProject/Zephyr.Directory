using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public class LdapObject
    {
        [JsonProperty(PropertyName = "dn", NullValueHandling = NullValueHandling.Ignore)]
        public string DistinguishedName { get; set; }

        [JsonProperty(PropertyName = "attributes", NullValueHandling = NullValueHandling.Ignore)]
        public Dictionary<string, object> Attributes { get; set; } = new Dictionary<string, object>();

    }
}
