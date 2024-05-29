using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

using Novell.Directory.Ldap;
using Zephyr.Crypto;


namespace Zephyr.Directory.Ldap
{
    [JsonConverter(typeof(StringEnumConverter))]
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

    [JsonConverter(typeof(StringEnumConverter))]
    public enum PingType
    {
        Echo,
        NoEcho
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum SearchScopeType
    {
        All = LdapConnection.ScopeSub,      // Search the base object and all entries within its subtree
        One = LdapConnection.ScopeOne,      // Search only the immediate subordinates of the base object
        Base = LdapConnection.ScopeBase     // Search only the base object
    }

    public class UnionType
    {
        [JsonProperty(PropertyName = "searchValue", NullValueHandling = NullValueHandling.Ignore)]
        public string SearchValue { get; set; }
 
        [JsonProperty(PropertyName = "searchBase", NullValueHandling = NullValueHandling.Ignore)]
        public string SearchBase { get; set; }
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
        public List<UnionType> Union { get; set; }

        [JsonProperty(PropertyName = "jobID", NullValueHandling = NullValueHandling.Ignore)]
        public string jobID { get; set; }

        [JsonProperty(PropertyName = "recordsID", NullValueHandling = NullValueHandling.Ignore)]
        public string recordsID { get; set; }

        [JsonProperty(PropertyName = "Timestamp", NullValueHandling = NullValueHandling.Ignore)]
        public string Timestamp { get; set; }

        [JsonProperty(PropertyName = "expireAt", NullValueHandling = NullValueHandling.Ignore)]
        public int expireAt { get; set; }
        
        [JsonProperty(PropertyName = "attributes", NullValueHandling = NullValueHandling.Ignore)]
        public List<string> Attributes { get; set; }    // null = ALL, empty list = NONE

        [JsonProperty(PropertyName = "config", NullValueHandling = NullValueHandling.Ignore)]
        public LdapConfig Config { get; set; }

        [JsonProperty(PropertyName = "crypto", NullValueHandling = NullValueHandling.Ignore)]
        public LdapCrypto Crypto { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        [JsonProperty(PropertyName = "ping", NullValueHandling = NullValueHandling.Ignore)]
        public PingType? Ping { get; set; }

        // Process the LDAP Request
        public LdapResponse Process()
        {
            LdapResponse response = new LdapResponse();
            bool isEncryptionRequest = this.Crypto?.Text != null;
            bool isPing = this.Ping.HasValue;

            if (isEncryptionRequest)
            {
                LdapCrypto crypto = LdapUtils.ApplyDefaulsAndValidate(this.Crypto);
                response.Message = Rijndael.Encrypt(crypto.Text, crypto.PassPhrase, crypto.SaltValue, crypto.InitVector);
            }
            else if (isPing)
            {
                System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
                System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(assembly.Location);
                string version = fvi.FileVersion;

                response.Message = "Hello From MyriAD (" + version + ").";
                if (this.Ping == PingType.Echo)
                    Console.WriteLine("Ping");
            }
            else
            {
                try
                {
                    LdapUtils.ApplyDefaulsAndValidate(this);
                    string searchFilter = LdapUtils.GetSearchString(this);
                    LdapServer ldap = new LdapServer(this.Config);
                    ldap.Bind(this.Config);
                    if (this.Config.TokenType == "Server" || this.Config.TokenType == "Client")
                    {
                        response = ldap.Search(this, this.SearchBase, searchFilter, this.Attributes, this.SearchScope, this.MaxResults, this.NextToken, this.Union);
                    }
                    else
                    {
                        throw new FormatException("Warning: TokenType must be set to Server or Client");
                    }
                    ldap.Disconnect();
                }
                catch (Exception e)
                {
                    response = LdapServer.ReturnError(e, this.Config);
                }
            }

            return response;
        }
    }
}
