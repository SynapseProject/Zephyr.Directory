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

            string content = File.ReadAllText(@"../../../TestFiles/myriad.json");
            LdapRequest request = JsonTools.Deserialize<LdapRequest>(content);
            Console.WriteLine(JsonTools.Serialize(request, true));

            bool isPing = request.Ping.HasValue;

            LdapResponse response = new LdapResponse();

            if (request.Crypto?.Text != null)
            {
                LdapUtils.ApplyDefaulsAndValidate(request.Crypto);
                response.Message = Rijndael.Encrypt(request.Crypto.Text, request.Crypto.PassPhrase, request.Crypto.SaltValue, request.Crypto.InitVector);
            }
            else if (isPing)
            {
                System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
                System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(assembly.Location);
                string version = fvi.FileVersion;

                response.Message = "Hello From MyriAD (" + version + ").";
                if (request.Ping == PingType.Echo)
                    Console.WriteLine("Ping");
            }
            else
            {
                try
                {
                    LdapUtils.ApplyDefaulsAndValidate(request);
                    string searchFilter = LdapUtils.GetSearchString(request);

                    LdapServer ldap = new LdapServer(request.Config);
                    ldap.Bind(request.Config);

                    response = ldap.Search(request.SearchBase, searchFilter, request.Attributes);
                    ldap.Disconnect();
                }
                catch (Exception e)
                {
                    response = LdapServer.ReturnError(e, request.Config);
                }
            }

            Console.WriteLine(JsonTools.Serialize(response, true));

        }
    }
}
