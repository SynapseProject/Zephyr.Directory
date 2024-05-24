using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Zephyr.Crypto;

using Zephyr.Directory.Ldap;

namespace Zephyr.Directory
{
    class Program
    {
        static void Main(string[] args)
        {
            string content = File.ReadAllText(@"../../../TestFiles/myriad.json");
            LdapRequest request = JsonTools.Deserialize<LdapRequest>(content);
            Console.WriteLine(JsonTools.Serialize(request, true));

            LdapResponse response = LdapEngine.Process(request);

            Console.WriteLine(JsonTools.Serialize(response, true));

        }
    }
}
