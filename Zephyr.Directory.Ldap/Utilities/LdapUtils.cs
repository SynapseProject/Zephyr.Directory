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

        public static LdapRequest ApplyDefaulsAndValidate(LdapRequest request)
        {
            // Set Config Defaults
            if (request.Config == null)
                request.Config = new LdapConfig();

            if (request.Config.Server == null)
                request.Config.Server = LdapUtils.GetEnvironmentVariable<string>("server", Environment.MachineName);

            if (request.Config.Port == null)
                request.Config.Port = LdapUtils.GetEnvironmentVariable<int>("port", 389);

            if (request.Config.UseSSL == null)
                request.Config.UseSSL = LdapUtils.GetEnvironmentVariable<bool>("useSSL", false);

            if (request.Config.Username == null)
                request.Config.Username = LdapUtils.GetEnvironmentVariable<string>("username");

            if (request.Config.Password == null)
                request.Config.Password = LdapUtils.GetEnvironmentVariable<string>("password");

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

            // Set Search Defaults
            if (request.SearchBase == null)
                request.SearchBase = LdapUtils.GetEnvironmentVariable<string>("searchBase");

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
