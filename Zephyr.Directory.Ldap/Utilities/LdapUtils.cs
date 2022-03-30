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
            string ntid = sAMAccountName.Replace('/', '\\');
            if (ntid.Contains('\\'))
                domain = ntid.Substring(0, ntid.IndexOf('\\'));

            return domain;
        }

        public static string GetDomainNameFromUPN(string username)
        {
            string domain = null;
            if (username.Contains('@'))
                domain = username.Substring(username.LastIndexOf('@') + 1);
            return domain;
        }

        public static LdapConfig GetConfigProfile(LdapRequest request)
        {
            LdapConfig config = new LdapConfig();
            Dictionary<string, string> configMap = LdapUtils.GetEnvironmentVariableJson<Dictionary<string, string>>("DOMAIN_CONFIGS");

            // Get Values From Request Config
            if (request.Config != null)
                SetConfigValues(config, request.Config);

            // Determine Domain Config From Request Values
            if (configMap != null)
            {
                // Get Values From Request Search Base
                if (request.SearchBase != null)
                {
                    string domain = GetDomainName(request.SearchBase);
                    LdapConfig sbConfig = GetConfigProfileFromMap(configMap, domain);
                    SetConfigValues(config, sbConfig);
                }

                // Get Values From Search Value
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

            Console.WriteLine(JsonTools.Serialize(request.Config, true));

            string attrConfigStr = LdapUtils.GetEnvironmentVariable<string>("returnTypes");
            if (!String.IsNullOrWhiteSpace(attrConfigStr))
            {
                LdapConfig envAttrConfig = JsonTools.Deserialize<LdapConfig>(attrConfigStr);
                if (request.Config.AttributeTypes == null)
                    request.Config.AttributeTypes = new Dictionary<string, LdapAttributeTypes>();

                foreach (string key in envAttrConfig.AttributeTypes.Keys)
                    if (!request.Config.AttributeTypes.ContainsKey(key))
                        request.Config.AttributeTypes.Add(key, envAttrConfig.AttributeTypes[key]);
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
                crypto.InitVector = LdapUtils.GetEnvironmentVariable<string>("iv", "1234567890ABCDEF");

            if (crypto.SaltValue == null)
                crypto.SaltValue = LdapUtils.GetEnvironmentVariable<string>("salt", "DefaultSaltValue");

            if (crypto.PassPhrase == null)
                crypto.PassPhrase = LdapUtils.GetEnvironmentVariable<string>("passphrase", "DefaultPassPhrase");

            return crypto;
        }

        public static string GetSearchString(LdapRequest request)
        {
            string searchFilter = null;

            if (request.ObjectType == null)
                searchFilter = request.SearchValue;
            else
            {
                string idSearchFilter = GetIdentitySearchString(request);
                searchFilter = $"(&(objectCategory={request.ObjectType.Value}){idSearchFilter})";
            }

            return searchFilter;
        }

        public static string GetIdentitySearchString(LdapRequest request)
        {
            string identity = null;
            Guid g = Guid.Empty;
            string dnRegexString = @"^\s*?(cn\s*=|ou\s*=|dc\s*=)";

            try { g = Guid.Parse(request.SearchValue); } catch { }

            if (g != Guid.Empty)
            {
                request.SearchBase = $"<GUID={g}>";
                identity = $"(cn=*)";
            }
            else if (SidUtils.IsSid(request.SearchValue))
            {
                request.SearchBase = $"<SID={request.SearchValue}>";
                identity = $"(cn=*)";
            }
            else if (Regex.IsMatch(request.SearchValue, dnRegexString, RegexOptions.IgnoreCase))
                identity = $"(distinguishedName={request.SearchValue})";
            else if (request.SearchValue.Contains('@') && request.ObjectType == ObjectType.User)     // Technically, both the CN and Name could contain an @ symbol as well
                identity = $"(|(cn={request.SearchValue})(name={request.SearchValue})(userPrincipalName={request.SearchValue}))";
            else
                identity = $"(|(cn={request.SearchValue})(name={request.SearchValue})(sAMAccountName={request.SearchValue}))";

            return identity;
        }
    }
}
