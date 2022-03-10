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

        // Known Active Directory Attributes That Do Not Default To "String" For Their Values.
        // These can be overridden in the config section.
        private static readonly Dictionary<string, LdapAttributeTypes> DefaultTypes = new Dictionary<string, LdapAttributeTypes>()
        {
            { "objectClass", LdapAttributeTypes.StringArray },
            { "managedObjects", LdapAttributeTypes.StringArray },
            { "dSCorePropagationData", LdapAttributeTypes.StringArray },
            { "objectGUID", LdapAttributeTypes.Guid },
            { "objectSid", LdapAttributeTypes.Sid },
            { "member", LdapAttributeTypes.StringArray },
            { "memberOf", LdapAttributeTypes.StringArray },
            { "proxyAddresses", LdapAttributeTypes.StringArray },
            { "businessCategory", LdapAttributeTypes.StringArray },
            { "otherHomePhone", LdapAttributeTypes.StringArray },
            { "otherPager", LdapAttributeTypes.StringArray },
            { "otherFacsimileTelephoneNumber", LdapAttributeTypes.StringArray },
            { "otherMobile", LdapAttributeTypes.StringArray },
            { "otherIpPhone", LdapAttributeTypes.StringArray },
            { "secretary", LdapAttributeTypes.StringArray },
        };

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

            foreach (string key in DefaultTypes.Keys)
                if (!(this.ReturnTypes.ContainsKey(key)))
                    this.ReturnTypes.Add(key, DefaultTypes[key]);

            this.conn = new LdapConnection();

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

        public LdapResponse Search(string searchBase, string searchFilter, List<string> attributes)
        {
            return Search(searchBase, searchFilter, attributes?.ToArray());
        }

        public LdapResponse Search(string searchBase, string searchFilter, string[] attributes = null)
        {
            LdapResponse response = new LdapResponse();

            try
            {
                if (!conn.Connected)
                {
                    response.Message = $"Server {this} Is Not Connected.";
                    response.Success = false;
                }

                if (!conn.Bound)
                {
                    response.Message = $"Server {this} Is Not Bound.";
                    response.Success = false;
                }

                if (searchBase == null)
                    searchBase = conn.GetRootDseInfo().DefaultNamingContext;

                LdapSearchResults results = null;
                if (attributes?.Length == 0)
                    results = (LdapSearchResults)conn.Search(searchBase, LdapConnection.ScopeSub, searchFilter, new string[] { "" }, false);
                else
                    results = (LdapSearchResults)conn.Search(searchBase, LdapConnection.ScopeSub, searchFilter, attributes, false);

                response = ParseResults(results);

            }
            catch (Exception e)
            {
                response.Message = e.Message;
                response.Success = false;
            }

            response.Server = this.ToString();
            response.SearchBase = searchBase;
            response.SearchFilter = searchFilter;

            return response;
        }

        private LdapResponse ParseResults(LdapSearchResults results)
        {
            LdapResponse response = new LdapResponse();
            response.Records = new List<LdapObject>();

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

                        if (attribute.ByteValueArray.Length > 1 && attrType != LdapAttributeTypes.BytesArray && attrType != LdapAttributeTypes.StringArray)
                            Console.WriteLine($"WARNING : Multi-Value Attribute [{attribute.Name}] Was Returned As A Single Value");
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
