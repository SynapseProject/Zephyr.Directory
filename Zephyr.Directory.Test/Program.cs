using System;
using System.Collections.Generic;

using Zephyr.Directory.Ldap;

namespace Zephyr.Directory
{
    class Program
    {
        static void Main(string[] args)
        {

            LdapConfig config = new LdapConfig();
            config.Server = LdapUtils.GetEnvironmentVariable<string>("server", Environment.MachineName);
            config.Port = LdapUtils.GetEnvironmentVariable<int>("port", 389);
            config.UseSSL = LdapUtils.GetEnvironmentVariable<bool>("useSSL", false);

            config.Username = LdapUtils.GetEnvironmentVariable<string>("username");
            config.Password = LdapUtils.GetEnvironmentVariable<string>("password");

            LdapSearch search = new LdapSearch();
            search.Base = LdapUtils.GetEnvironmentVariable<string>("searchBase", "dc=sandbox,dc=local");
            search.Filter = LdapUtils.GetEnvironmentVariable<string>("searchFilter", "(samAccountName=wagug0)");
            search.Attributes = new List<string>();

            LdapRequest request = new LdapRequest();
            request.Config = config;
            request.Search = search;

            LdapServer.Test(request);
        }
    }
}
