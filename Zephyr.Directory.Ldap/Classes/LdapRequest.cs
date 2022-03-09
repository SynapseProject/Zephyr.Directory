using System;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public enum RequestType
    {
        Search,
        Encrypt
    }

    public class LdapRequest
    {
        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(PropertyName = "type", NullValueHandling = NullValueHandling.Ignore)]
        public RequestType Type { get; set; }

        [JsonProperty(PropertyName = "value", NullValueHandling = NullValueHandling.Ignore)]
        public string Value { get; set; }

        [JsonProperty(PropertyName = "config", NullValueHandling = NullValueHandling.Ignore)]
        public LdapConfig Config { get; set; }

        [JsonProperty(PropertyName = "search", NullValueHandling = NullValueHandling.Ignore)]
        public LdapSearch Search { get; set; }

        [JsonProperty(PropertyName = "crypto", NullValueHandling = NullValueHandling.Ignore)]
        public LdapCrypto Crypto { get; set; }
    }
}
