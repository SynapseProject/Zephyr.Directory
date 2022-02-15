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
        public static void Test(LdapRequest request)
        {
            LdapConfig config = request.Config;
            LdapSearch search = request.Search;

            if (config.UseSSL)
                Console.WriteLine($"Connecting To Server : ldaps://{config.Server}:{config.Port}");
            else
                Console.WriteLine($"Connecting To Server : ldap://{config.Server}:{config.Port}");

            LdapConnection ldap = new LdapConnection();
            ldap.SecureSocketLayer = config.UseSSL;
            if (config.UseSSL)
                ldap.UserDefinedServerCertValidationDelegate += (sender, certificate, chain, errors) => true;
            ldap.Connect(config.Server, config.Port);

            ldap.Bind(LdapConnection.LdapV3, config.Username, config.Password);

            LdapSearchResults results = null;
            if (search.Attributes?.Count == 0)
                results = (LdapSearchResults)ldap.Search(search.Base, LdapConnection.ScopeSub, search.Filter, new string[] { "" }, false);
            else
                results = (LdapSearchResults)ldap.Search(search.Base, LdapConnection.ScopeSub, search.Filter, search.Attributes?.ToArray(), false);

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
