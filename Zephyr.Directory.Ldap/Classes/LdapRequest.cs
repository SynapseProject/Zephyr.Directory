using System;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public class LdapRequest
    {
        [JsonProperty(PropertyName = "config", NullValueHandling = NullValueHandling.Ignore)]
        public LdapConfig Config { get; set; }

        [JsonProperty(PropertyName = "search", NullValueHandling = NullValueHandling.Ignore)]
        public LdapSearch Search { get; set; }

        [JsonProperty(PropertyName = "crypto", NullValueHandling = NullValueHandling.Ignore)]
        public Crypto Crypto { get; set; }
    }
}
