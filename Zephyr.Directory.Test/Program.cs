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
            LdapServer.Test(request);
        }
    }
}
