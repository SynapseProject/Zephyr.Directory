using System;
using System.Collections.Generic;
using System.IO;

using Zephyr.Directory.Ldap;

namespace Zephyr.Directory
{
    class Program
    {
        static void Main(string[] args)
        {
            string content = File.ReadAllText(@"/Users/guy/Desktop/myriad.json");
            LdapRequest request = JsonTools.Deserialize<LdapRequest>(content);
            Console.WriteLine(JsonTools.Serialize(request, true));

            LdapUtils.ApplyDefaulsAndValidate(request);

            LdapServer ldap = new LdapServer(request.Config);
            ldap.Connect();
            ldap.Bind(request.Config);

            LdapResponse response = ldap.Search(request.Search);

            Console.WriteLine(JsonTools.Serialize(response, true));

            ldap.Disconnect();
        }
    }
}
