using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public enum ObjectType
    {
        User,
        Group
    }

    public class LdapRequest
    {
        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(PropertyName = "objectType", NullValueHandling = NullValueHandling.Ignore)]
        public ObjectType? ObjectType { get; set; }

        [JsonProperty(PropertyName = "searchValue", NullValueHandling = NullValueHandling.Ignore)]
        public string SearchValue { get; set; }

        [JsonProperty(PropertyName = "searchBase", NullValueHandling = NullValueHandling.Ignore)]
        public string SearchBase { get; set; }

        [JsonProperty(PropertyName = "attributes", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Attributes { get; set; }    // null = ALL, empty list = NONE

        [JsonProperty(PropertyName = "config", NullValueHandling = NullValueHandling.Ignore)]
        public LdapConfig Config { get; set; }

        [JsonProperty(PropertyName = "crypto", NullValueHandling = NullValueHandling.Ignore)]
        public LdapCrypto Crypto { get; set; }
    }
}
