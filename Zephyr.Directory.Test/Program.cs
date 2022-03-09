using System;
using System.Collections.Generic;
using System.IO;

using Zephyr.Crypto;

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

            LdapResponse response = new LdapResponse();
            response.Type = request.Type;

            LdapUtils.ApplyDefaulsAndValidate(request);

            if (request.Type == RequestType.Encrypt)
                response.Value = Rijndael.Encrypt(request.Value, request.Crypto.PassPhrase, request.Crypto.SaltValue, request.Crypto.InitVector);
            else
            {
                LdapServer ldap = new LdapServer(request.Config);
                ldap.Connect();
                ldap.Bind(request.Config);

                response = ldap.Search(request.Search);
                ldap.Disconnect();
            }

            Console.WriteLine(JsonTools.Serialize(response, true));

        }
    }
}
