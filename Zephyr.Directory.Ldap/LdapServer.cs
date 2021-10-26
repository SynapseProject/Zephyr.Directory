using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


using System.Text;
using System.Collections;
using System.Collections.Generic;

using Novell.Directory.Ldap;
using Novell.Directory.Ldap.SearchExtensions;
using Novell.Directory.Ldap.Utilclass;

namespace Zephyr.Directory.Ldap
{
    public class LdapServer
    {
        public static void Test()
        {
            string server = LdapUtils.GetEnvironmentVariable<string>("server", Environment.MachineName);
            int port = LdapUtils.GetEnvironmentVariable<int>("port", 389);
            bool useSSL = LdapUtils.GetEnvironmentVariable<bool>("useSSL", false);

            string searchBase = LdapUtils.GetEnvironmentVariable<string>("searchBase", "dc=sandbox,dc=local");
            string searchFilter = LdapUtils.GetEnvironmentVariable<string>("searchFilter", "(samAccountName=wagug0)");
            string[] searchAttributes = null;
            //{
            //    "objectGUID"
            //};

            string username = LdapUtils.GetEnvironmentVariable<string>("username");
            string password = LdapUtils.GetEnvironmentVariable<string>("password");

            if (useSSL)
                Console.WriteLine($"Connecting To Server : ldaps://{server}:{port}");
            else
                Console.WriteLine($"Connecting To Server : ldap://{server}:{port}");

            LdapConnection ldap = new LdapConnection();
            ldap.SecureSocketLayer = useSSL;
            if (useSSL)
                ldap.UserDefinedServerCertValidationDelegate += (sender, certificate, chain, errors) => true;
            ldap.Connect(server, port);

            ldap.Bind(LdapConnection.LdapV3, username, password);

            LdapSearchResults results = (LdapSearchResults)ldap.Search(searchBase, LdapConnection.ScopeSub, searchFilter, searchAttributes, false);

            while (results.HasMore())
            {
                try
                {
                    LdapEntry record = results.Next();
                    Console.WriteLine($">> {record.Dn}");

                    LdapAttributeSet attributes = record.GetAttributeSet();
                    foreach (string key in attributes.Keys)
                    {
                        LdapAttribute attribute = attributes[key];
                        string name = attribute.Name;
                        string value = attribute.StringValue;



                        Console.WriteLine($"   - {name} : {value}");
                    }

                }
                catch (LdapReferralException)
                {
                    continue;
                }

            }

            ldap.Disconnect();
        }

        public static bool MySSLHandler(X509Certificate certificate, int[] certificateErrors)
        {

            //X509Store store = null;
            //X509Stores stores = X509StoreManager.CurrentUser;
            ////string input;
            //store = stores.TrustedRoot;

            //X509Certificate x509 = null;
            //X509CertificateCollection coll = new X509CertificateCollection();
            //byte[] data = certificate.GetRawCertData();
            //if (data != null)
            //    x509 = new X509Certificate(data);

            return true;
        }
    }
}
