using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public enum LdapAttributeTypes
    {
        String,
        StringArray,
        Bytes,
        BytesArray,
        Guid,
        Sid
    }

    public class LdapConfig
    {
        [JsonProperty(PropertyName = "server", NullValueHandling = NullValueHandling.Ignore)]
        public string Server { get; set; }

        [JsonProperty(PropertyName = "port", NullValueHandling = NullValueHandling.Ignore)]
        public int? Port { get; set; }

        [JsonProperty(PropertyName = "ssl", NullValueHandling = NullValueHandling.Ignore)]
        public bool? UseSSL { get; set; }

        [JsonProperty(PropertyName = "username", NullValueHandling = NullValueHandling.Ignore)]
        public string Username { get; set; }

        [JsonProperty(PropertyName = "password", NullValueHandling = NullValueHandling.Ignore)]
        public string Password { get; set; }

        [JsonProperty(PropertyName = "returnTypes", NullValueHandling = NullValueHandling.Ignore)]
        public Dictionary<string, LdapAttributeTypes> AttributeTypes { get; set; }

    }
}
