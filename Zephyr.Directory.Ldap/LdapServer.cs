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
        LdapConnection conn;

        public string Server { get; set; }
        public int Port { get; set; }
        public bool UseSSL { get; set; }

        public LdapServer(LdapConfig config)
        {
            init(config.Server, config.Port.Value, config.UseSSL.Value);
        }

        public LdapServer(string server, int port, bool useSSL)
        {
            init(server, port, useSSL);
        }

        public override string ToString()
        {
            if (this.UseSSL)
                return $"ldaps://{this.Server}:{this.Port}";
            else
                return $"ldap://{this.Server}:{this.Port}";
        }

        private void init(string server, int port, bool useSSL)
        {
            this.Server = server;
            this.Port = port;
            this.UseSSL = useSSL;

            this.conn = new LdapConnection();

            Console.WriteLine($"LDAP Server   : {this}");

            conn.SecureSocketLayer = this.UseSSL;
            if (this.UseSSL)
                conn.UserDefinedServerCertValidationDelegate += (sender, certificate, chain, errors) => true;

            this.Connect();
        }

        public void Connect()
        {
            if (!conn.Connected)
                conn.Connect(this.Server, this.Port);
        }

        public void Disconnect()
        {
            if (conn.Connected)
                conn.Disconnect();
        }

        public void Bind(LdapConfig config)
        {
            Bind(config.Username, config.Password);
        }

        public void Bind(string username, string password)
        {
            conn.Bind(LdapConnection.LdapV3, username, password);
        }

        public LdapResponse Search(LdapSearch search)
        {
            return Search(search.Base, search.Filter, search.Attributes);
        }

        public LdapResponse Search(string searchBase, string searchFilter, List<string> attributes)
        {
            return Search(searchBase, searchFilter, attributes?.ToArray());
        }

        public LdapResponse Search(string searchBase, string searchFilter, string[] attributes = null)
        {
            if (!conn.Connected)
                throw new Exception($"Server {this} Is Not Connected.");

            if (!conn.Bound)
                throw new Exception($"Server {this} Is Not Bound.");

            if (searchBase == null)
                searchBase = conn.GetRootDseInfo().DefaultNamingContext;

            Console.WriteLine($"Search Base   : {searchBase}");
            Console.WriteLine($"Search Filter : {searchFilter}");

            LdapSearchResults results = null;
            if (attributes?.Length == 0)
                results = (LdapSearchResults)conn.Search(searchBase, LdapConnection.ScopeSub, searchFilter, new string[] { "" }, false);
            else
                results = (LdapSearchResults)conn.Search(searchBase, LdapConnection.ScopeSub, searchFilter, attributes, false);

            LdapResponse response = ParseResults(results);
            response.SearchBase = searchBase;
            response.SearchFilter = searchFilter;
            return response;
        }

        private LdapResponse ParseResults(LdapSearchResults results)
        {
            LdapResponse response = new LdapResponse();

            while (results.HasMore())
            {
                try
                {
                    LdapEntry record = results.Next();

                    LdapObject rec = new LdapObject();
                    rec.DistinguishedName = record.Dn;

                    LdapAttributeSet attributes = record.GetAttributeSet();
                    rec.Attributes = new Dictionary<string, object>();

                    foreach (string key in attributes.Keys)
                    {
                        LdapAttribute attribute = attributes[key];
                        Type type = attribute.GetType();
                        string value = attribute.StringValue;
                        if (key == "objectGUID")
                            value = new Guid(attribute.ByteValue).ToString();
                        if (key == "objectSid")
                            value = LdapUtils.ConvertByteToStringSid(attribute.ByteValue);


                        rec.Attributes.Add(key, value);
                    }

                    response.Records.Add(rec);
                }
                catch (LdapReferralException)
                {
                    continue;
                }
            }

            return response;
        }

        private bool MySSLHandler(X509Certificate certificate, int[] certificateErrors)
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
