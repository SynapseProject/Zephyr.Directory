using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

using Novell.Directory.Ldap;


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
        DomainController,       // (&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))
        Dn,                     // Shorthand for DistinguishedName
        DistinguishedName       // Returns object by DistinguishedName
    }

    public enum PingType
    {
        Echo,
        NoEcho
    }

    public enum SearchScopeType
    {
        All = LdapConnection.ScopeSub,      // Search the base object and all entries within its subtree
        One = LdapConnection.ScopeOne,      // Search only the immediate subordinates of the base object
        Base = LdapConnection.ScopeBase     // Search only the base object
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

        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(PropertyName = "searchScope", NullValueHandling = NullValueHandling.Ignore)]
        public SearchScopeType? SearchScope { get; set; }

        [JsonProperty(PropertyName = "maxResults", NullValueHandling = NullValueHandling.Ignore)]
        public int? MaxResults { get; set; }

        [JsonProperty(PropertyName = "nextToken", NullValueHandling = NullValueHandling.Ignore)]
        public string NextToken { get; set; }

        [JsonProperty(PropertyName = "wildcardSearch", NullValueHandling = NullValueHandling.Ignore)]
        public bool? WildcardSearch { get; set; }

        [JsonProperty(PropertyName = "union", NullValueHandling = NullValueHandling.Ignore)]
        public List<Dictionary<string, string>> Union { get; set; }

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
