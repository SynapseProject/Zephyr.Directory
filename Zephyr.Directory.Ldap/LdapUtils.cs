using System;
using System.Collections.Generic;

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

            // Set Search Defaults
            if (request.Search == null)
                request.Search = new LdapSearch();

            if (request.Search.Base == null)
                request.Search.Base = LdapUtils.GetEnvironmentVariable<string>("searchBase");

            // Validate Request
            if (request.Search.Filter == null)
                throw new Exception("Search Filter Not Provided.");

            return request;
        }

    }
}
