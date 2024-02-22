using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public enum LdapAttributeTypes
    {
        Unknown,            // Return type is Unknown.  Return value(s) will be evaulated and a best guess at return type will be made.
        String,             // Return as a String ( ex: "Two" )
        StringArray,        // Return as a list of String ( ex: ["Two","Three","One","Four"] )
        Bytes,              // Return as a Hex String ( ex: "0x54776F" )
        BytesArray,         // Return as a list of Hex Strings ( ex: ["0x54776F","0x5468726565","0x4F6E65","0x466F7572"] )
        Guid,               // Return as a String representation of a Guid ( ex: "487eff5a-b915-4a3c-8528-79cc0ffc774e" )
        GuidArray,          // Return as a list of Guids (ex: [ "487eff5a-b915-4a3c-8528-79cc0ffc774e", "abcdefgh-ijkl-mnop-qrst-uvwxyz123456" ] )
        Sid,                // Return as a String representation of a Security Identifier ( ex: "S-1-5-21-4054027134-3251639354-3875066094-7561" )
        SidArray,           // Return as a list of Security Identifiers (ex: [ "S-1-5-21-4054027134-3251639354-3875066094-7561", "S-1-5-21-4054027134-3251639354-3875066094-1234" ]
        Number,             // Return as a Number ( ex: "value": 42 )
        NumberArray,        // Return as a list of Numbers ( ex: [ 867, 5309 ]
        Boolean,            // Return as a Boolean ( ex: "value": true }
        BooleanArray        // Return as a list of Booleans ( ex: [ true, true, false ] )
    }

    public class LdapConfig
    {
        [JsonProperty(PropertyName = "server", NullValueHandling = NullValueHandling.Ignore)]
        public string Server { get; set; }
        
        [JsonProperty(PropertyName = "TokenType", NullValueHandling = NullValueHandling.Ignore)]
        public string TokenType { get; set; }

        [JsonProperty(PropertyName = "port", NullValueHandling = NullValueHandling.Ignore)]
        public int? Port { get; set; }

        [JsonProperty(PropertyName = "ssl", NullValueHandling = NullValueHandling.Ignore)]
        public bool? UseSSL { get; set; }

        [JsonProperty(PropertyName = "username", NullValueHandling = NullValueHandling.Ignore)]
        public string Username { get; set; }

        [JsonProperty(PropertyName = "password", NullValueHandling = NullValueHandling.Ignore)]
        public string Password { get; set; }

        [JsonProperty(PropertyName = "maxRetries", NullValueHandling = NullValueHandling.Ignore)]
        public int? MaxRetries { get; set; }

        [JsonProperty(PropertyName = "maxPageSize", NullValueHandling = NullValueHandling.Ignore)]
        public int? MaxPageSize { get; set; }

        [JsonProperty(PropertyName = "followReferrals", NullValueHandling = NullValueHandling.Ignore)]
        public bool? FollowReferrals { get; set; }

        [JsonProperty(PropertyName = "ignoreWarnings", NullValueHandling = NullValueHandling.Ignore)]
        public bool? IgnoreWarnings { get; set; }

        [JsonProperty(PropertyName = "returnTypes", NullValueHandling = NullValueHandling.Ignore, ItemConverterType = typeof(StringEnumConverter))]
        public Dictionary<string, LdapAttributeTypes> AttributeTypes { get; set; }

    }
}
