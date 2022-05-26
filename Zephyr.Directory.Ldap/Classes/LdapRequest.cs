using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;


namespace Zephyr.Directory.Ldap
{
    public enum ObjectType
    {
        User,                   // User and Contact Objects
        Group,                  
        OrganizationalUnit,
        Ou,                     // Shorthand for OrganizationalUnit
        Contact,                // Contact Objects Only
        PrintQueue,
        Printer,                // Same As PrintQueue             
        Computer,
        Volume,                 // Shared Folder
        Domain,
        DomainController        // (&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))
    }

    public enum PingType
    {
        Echo,
        NoEcho
    }

    public class LdapRequest
    {
        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(PropertyName = "objectType", NullValueHandling = NullValueHandling.Ignore)]
        public ObjectType? ObjectType { get; set; }

        [JsonProperty(PropertyName = "domain", NullValueHandling = NullValueHandling.Ignore)]
        public string Domain { get; set; }

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

        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(PropertyName = "ping", NullValueHandling = NullValueHandling.Ignore)]
        public PingType? Ping { get; set; }
    }
}
