using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public enum LdapAttributeTypes
    {
        String,             // Return as a String ( ex: "Two" )
        StringArray,        // Return as a list of String ( ex: ["Two","Three","One","Four"] )
        Bytes,              // Return as a Hex String ( ex: "0x54776F" )
        BytesArray,         // Return as a list of Hex Strings ( ex: ["0x54776F","0x5468726565","0x4F6E65","0x466F7572"] )
        Guid,               // Return as a String representation of a Guid ( ex: "487eff5a-b915-4a3c-8528-79cc0ffc774e" )
        Sid                 // Return as a String representation of a Security Identifier ( ex: "S-1-5-21-4054027134-3251639354-3875066094-7561" )
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

        [JsonProperty(PropertyName = "maxResults", NullValueHandling = NullValueHandling.Ignore)]
        public int? MaxResults { get; set; }

        [JsonProperty(PropertyName = "returnTypes", NullValueHandling = NullValueHandling.Ignore, ItemConverterType = typeof(StringEnumConverter))]
        public Dictionary<string, LdapAttributeTypes> AttributeTypes { get; set; }

    }
}
