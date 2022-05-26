using System;
using System.Text;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Zephyr.Crypto;

namespace Zephyr.Directory.Ldap
{
    public class LdapUtils
    {
        public static string GetEnvironmentVariable(string name, string defaultValue = null)
        {
            return GetEnvironmentVariable<string>(name, defaultValue);
        }

        public static T GetEnvironmentVariable<T>(string name)
        {
            return GetEnvironmentVariable<T>(name, (T)Convert.ChangeType(null, typeof(T)));
        }

        public static T GetEnvironmentVariable<T>(string name, T defaultValue) 
        {
            string value = Environment.GetEnvironmentVariable(name);

            if (value == null)
                value = defaultValue?.ToString();

            return (T)Convert.ChangeType(value, typeof(T));
        }

        public static T GetEnvironmentVariableJson<T>(string name, T defaultValue = default(T))
        {
            string value = Environment.GetEnvironmentVariable(name);

            if (value == null)
                return defaultValue;
            else
                return JsonTools.Deserialize<T>(value);
        }

        public static string GetDomainName(string distinguisedName)
        {
            String pattern = @"DC=([^,]+)";
            List<string> parts = new List<string>();
            Regex r = new Regex(pattern);
            MatchCollection mc = r.Matches(distinguisedName);
            foreach (Match m in mc)
                if (m.Groups[1]?.Value != null)
                    parts.Add(m.Groups[1].Value);

            return String.Join(".", parts.ToArray());

        }

        public static string GetDomainDistinguishedName(string domain)
        {
            string[] parts = domain.Split('.');
            for (int i = 0; i < parts.Length; i++)
                parts[i] = $"DC={parts[i]}";
            return String.Join(",", parts);
        }

        public static string GetDomainShortName(string sAMAccountName)
        {
            string domain = null;
            if (!String.IsNullOrEmpty(sAMAccountName))
            {
                string ntid = sAMAccountName.Replace('/', '\\');
                if (ntid.Contains('\\'))
                    domain = ntid.Substring(0, ntid.IndexOf('\\'));
            }
            return domain;
        }

        public static string GetDomainNameFromUPN(string username)
        {
            string domain = null;
            if (!String.IsNullOrWhiteSpace(username))
            {
                if (username.Contains('@'))
                    domain = username.Substring(username.LastIndexOf('@') + 1);
            }
            return domain;
        }

        public static LdapConfig GetConfigProfile(LdapRequest request)
        {
            LdapConfig config = new LdapConfig();
            Dictionary<string, string> configMap = LdapUtils.GetEnvironmentVariableJson<Dictionary<string, string>>("DOMAIN_MAPPINGS");

            // Get Values From Request Config
            if (request.Config != null)
                SetConfigValues(config, request.Config);

            // Use Provided Domain Information
            if (request.Domain != null)
            {
                LdapConfig dmConfig = null;
                if (configMap != default(Dictionary<string, string>))
                    dmConfig = GetConfigProfileFromMap(configMap, request.Domain);

                if (dmConfig == null)
                    dmConfig = LdapUtils.GetEnvironmentVariableJson<LdapConfig>(request.Domain.ToUpper());

                if (dmConfig != null)
                    SetConfigValues(config, dmConfig);

                //TODO : Throw Error Since Provided Domain Not Found????
            }

            // Determine Domain Config From Request Values
            else if (configMap != default(Dictionary<string,string>))
            {
                // Get Values From Request Search Base
                if (request.SearchBase != null)
                {
                    string domain = GetDomainName(request.SearchBase);
                    LdapConfig sbConfig = GetConfigProfileFromMap(configMap, domain);
                    SetConfigValues(config, sbConfig);
                }

                // Get Values From Search Value
                if (!String.IsNullOrWhiteSpace(request.SearchValue))
                {
                    string domainKey = null;
                    LdapConfig svConfig = null;

                    // Check For Domain Short Name (DOMAIN\\sAMAccountName)
                    if (svConfig == null)
                    {
                        domainKey = GetDomainShortName(request.SearchValue);
                        svConfig = GetConfigProfileFromMap(configMap, domainKey);
                    }

                    // Check For Domain from UserPrincipal Name (user@domain)
                    if (svConfig == null)
                    {
                        domainKey = GetDomainNameFromUPN(request.SearchValue);
                        svConfig = GetConfigProfileFromMap(configMap, domainKey);
                    }

                    // Check For Domain from DistinguishedName
                    if (svConfig == null)
                    {
                        domainKey = GetDomainName(request.SearchValue);
                        svConfig = GetConfigProfileFromMap(configMap, domainKey);
                    }

                    // If Domain Found From Search Value, Apply It
                    if (svConfig != null)
                        SetConfigValues(config, svConfig);
                }
            }

            // Get Values From Default Environment Variable (DEFAULT_CONFIG)
            LdapConfig envConfig = GetEnvironmentVariableJson<LdapConfig>("DEFAULT_CONFIG");
            SetConfigValues(config, envConfig);

            // Finally, Apply Default Values If Still Null
            if (config.Server == null)
                config.Server = Environment.MachineName;

            if (config.UseSSL == null)
                config.UseSSL = false;

            if (config.Port == null)
                config.Port = config.UseSSL == true ? 636 : 389;

            return config;
        }

        private static LdapConfig GetConfigProfileFromMap(Dictionary<string,string> map, string key)
        {
            LdapConfig config = null;
            if (key != null)
            {
                string upKey = key?.ToUpper();
                if (map.ContainsKey(upKey))
                    config = LdapUtils.GetEnvironmentVariableJson<LdapConfig>(map[upKey]);
            }

            return config;
        }

        private static LdapConfig SetConfigValues(LdapConfig target, LdapConfig source)
        {
            if (source == null)
                return target;

            if (target.Server == null)
                target.Server = source.Server;

            if (target.Port == null)
                target.Port = source.Port;

            if (target.UseSSL == null)
                target.UseSSL = source.UseSSL;

            if (target.Username == null)
                target.Username = source.Username;

            if (target.Password == null)
                target.Password = source.Password;

            if (target.MaxResults == null)
                target.MaxResults = source.MaxResults;

            return target;
        }

        public static LdapRequest ApplyDefaulsAndValidate(LdapRequest request)
        {
            // Set Config Defaults
            request.Config = GetConfigProfile(request);

            string attrConfigStr = LdapUtils.GetEnvironmentVariable<string>("RETURN_TYPES");
            if (!String.IsNullOrWhiteSpace(attrConfigStr))
            {
                Dictionary<string, LdapAttributeTypes> returnTypes = JsonTools.Deserialize<Dictionary<string, LdapAttributeTypes>>(attrConfigStr);
                if (request.Config.AttributeTypes == null)
                    request.Config.AttributeTypes = new Dictionary<string, LdapAttributeTypes>();

                foreach (string key in returnTypes.Keys)
                    if (!request.Config.AttributeTypes.ContainsKey(key))
                        request.Config.AttributeTypes.Add(key, returnTypes[key]);
            }

            // Set Crypto Defaults
            request.Crypto = ApplyDefaulsAndValidate(request.Crypto);

            // Attempt To Decrypt Password
            try { request.Config.Password = Rijndael.Decrypt(request.Config.Password, request.Crypto.PassPhrase, request.Crypto.SaltValue, request.Crypto.InitVector); }
            catch { }

            return request;
        }

        public static LdapCrypto ApplyDefaulsAndValidate(LdapCrypto crypto)
        {
            // Set Crypto Defaults
            if (crypto == null)
                crypto = new LdapCrypto();

            if (crypto.InitVector == null)
                crypto.InitVector = LdapUtils.GetEnvironmentVariable<string>("IV", "1234567890ABCDEF");

            if (crypto.SaltValue == null)
                crypto.SaltValue = LdapUtils.GetEnvironmentVariable<string>("SALT", "DefaultSaltValue");

            if (crypto.PassPhrase == null)
                crypto.PassPhrase = LdapUtils.GetEnvironmentVariable<string>("PASSPHRASE", "DefaultPassPhrase");

            return crypto;
        }

        public static string GetSearchString(LdapRequest request)
        {
            string searchFilter = null;

            if (request.ObjectType == null)
                searchFilter = request.SearchValue;
            else
            {
                string id = GetIdentitySearchString(request);

                if (request.ObjectType == ObjectType.Ou)
                    searchFilter = $"(&(objectCategory=OrganizationalUnit){id})";
                else if (request.ObjectType == ObjectType.Contact)
                    searchFilter = $"(&(objectCategory=Person)(objectClass=Contact){id})";
                else if (request.ObjectType == ObjectType.DomainController)
                    searchFilter = $"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192){id})";
                else if (request.ObjectType == ObjectType.Printer)
                    searchFilter = $"(&(objectCategory=PrintQueue){id})";
                else
                    searchFilter = $"(&(objectCategory={request.ObjectType.Value}){id})";
            }

            return searchFilter;
        }

        public static string GetIdentitySearchString(LdapRequest request)
        {
            string identity = null;
            string searchValue = request.SearchValue;
            Guid g = Guid.Empty;
            string dnRegexString = @"^\s*?(cn\s*=|ou\s*=|dc\s*=)";

            if (ContainsKnownDomain(searchValue))
            {
                // Strip Out Known Domain and Search ( DOMAIN\value )
                searchValue = searchValue.Replace('/', '\\');
                searchValue = searchValue.Substring(searchValue.IndexOf('\\') + 1);
            }

            try { g = Guid.Parse(searchValue); } catch { }

            if (g != Guid.Empty)
            {
                request.SearchBase = $"<GUID={g}>";
                identity = $"(cn=*)";
            }
            else if (SidUtils.IsSid(searchValue))
            {
                request.SearchBase = $"<SID={searchValue}>";
                identity = $"(cn=*)";
            }
            else if (Regex.IsMatch(searchValue, dnRegexString, RegexOptions.IgnoreCase))
                identity = $"(distinguishedName={searchValue})";
            else if (searchValue.Contains('@') && request.ObjectType == ObjectType.User)     // Technically, both the CN and Name could contain an @ symbol as well
                identity = $"(|(cn={searchValue})(name={searchValue})(userPrincipalName={searchValue}))";
            else
            {
                if (request.ObjectType == ObjectType.Contact || request.ObjectType == ObjectType.Printer || request.ObjectType == ObjectType.PrintQueue || request.ObjectType == ObjectType.Volume)
                    identity = $"(|(cn={searchValue})(name={searchValue}))";
                else if (request.ObjectType == ObjectType.Ou || request.ObjectType == ObjectType.OrganizationalUnit)
                    identity = $"(|(ou={searchValue})(name={searchValue}))";
                else if (request.ObjectType == ObjectType.Domain)
                    identity = $"(name={searchValue})";
                else
                    identity = $"(|(cn={searchValue})(name={searchValue})(sAMAccountName={searchValue}))";
            }

            return identity;
        }

        public static bool ContainsKnownDomain(string value)
        {
            bool rc = false;

            if (value.Contains('\\') || value.Contains('/'))
            {
                Dictionary<string, string> configMap = LdapUtils.GetEnvironmentVariableJson<Dictionary<string, string>>("DOMAIN_MAPPINGS");
                if (configMap != default(Dictionary<string,string>))
                {
                    String domainShortName = GetDomainShortName(value);
                    if (domainShortName != null && configMap.ContainsKey(domainShortName.ToUpper()))
                        rc = true;
                }
            }

            return rc;
        }
    }
}
