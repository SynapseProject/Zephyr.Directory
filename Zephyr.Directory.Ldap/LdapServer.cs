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
        public Dictionary<string, LdapAttributeTypes> ReturnTypes { get; set; }

        public LdapServer(LdapConfig config)
        {
            init(config.Server, config.Port.Value, config.UseSSL.Value, config.AttributeTypes);
        }

        public LdapServer(string server, int port, bool useSSL, Dictionary<string, LdapAttributeTypes> attributeReturnTypes = null)
        {
            init(server, port, useSSL, attributeReturnTypes);
        }

        public override string ToString()
        {
            if (this.UseSSL)
                return $"ldaps://{this.Server}:{this.Port}";
            else
                return $"ldap://{this.Server}:{this.Port}";
        }

        private void init(string server, int port, bool useSSL, Dictionary<string, LdapAttributeTypes> attributeReturnTypes = null)
        {
            this.Server = server;
            this.Port = port;
            this.UseSSL = useSSL;
            this.ReturnTypes = attributeReturnTypes;
            if (this.ReturnTypes == null)
                this.ReturnTypes = new Dictionary<string, LdapAttributeTypes>();

            // Unless Specified, Return the "objectGUID" attrubute as a Guid string
            if (!this.ReturnTypes.ContainsKey("objectGUID"))
                this.ReturnTypes.Add("objectGUID", LdapAttributeTypes.Guid);

            // Unless Specified, Return the "objectSid" attribute as a Security Identifier string
            if (!this.ReturnTypes.ContainsKey("objectSid"))
                this.ReturnTypes.Add("objectSid", LdapAttributeTypes.Sid);

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

                        LdapAttributeTypes attrType = LdapAttributeTypes.String;
                        if (this.ReturnTypes.ContainsKey(key))
                            attrType = this.ReturnTypes[key];

                        switch (attrType)
                        {
                            case LdapAttributeTypes.Bytes:
                                string str = BitConverter.ToString(attribute.ByteValue);
                                str = str.Replace("-", "");
                                rec.Attributes.Add(key, "0x" + str);
                                break;
                            case LdapAttributeTypes.BytesArray:
                                List<string> strs = new List<string>();
                                foreach (byte[] b in attribute.ByteValueArray)
                                {
                                    string s = BitConverter.ToString(b);
                                    strs.Add("0x" + s.Replace("-", ""));
                                }
                                rec.Attributes.Add(key, strs);
                                break;
                            case LdapAttributeTypes.Guid:
                                rec.Attributes.Add(key, new Guid(attribute.ByteValue).ToString());
                                break;
                            case LdapAttributeTypes.Sid:
                                rec.Attributes.Add(key, LdapUtils.ConvertByteToStringSid(attribute.ByteValue));
                                break;
                            case LdapAttributeTypes.StringArray:
                                rec.Attributes.Add(key, attribute.StringValueArray);
                                break;
                            default:
                                rec.Attributes.Add(key, attribute.StringValue);
                                break;

                        }

                        string value = attribute.StringValue;
                        if (key == "objectGUID")
                            value = new Guid(attribute.ByteValue).ToString();
                        if (key == "objectSid")
                            value = LdapUtils.ConvertByteToStringSid(attribute.ByteValue);
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
