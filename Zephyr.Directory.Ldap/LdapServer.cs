using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


using System.Text;
using System.Collections;
using System.Collections.Generic;

using LdapForNet;
using LdapForNet.Native;

//using Novell.Directory.Ldap;
//using Novell.Directory.Ldap.SearchExtensions;
//using Novell.Directory.Ldap.Utilclass;

namespace Zephyr.Directory.Ldap
{
    public partial class LdapServer
    {
        LdapConnection conn;

        public string Server { get; set; }
        public int Port { get; set; }
        public bool UseSSL { get; set; }
        public int MaxResults { get; set; } = 1000;
        public int MaxRetries { get; set; } = 0;
        public Dictionary<string, LdapAttributeTypes> ReturnTypes { get; set; }

        public LdapServer(LdapConfig config)
        {
            init(config.Server, config.Port.Value, config.UseSSL.Value, config.MaxResults, config.MaxRetries, config.AttributeTypes);
        }

        public LdapServer(string server, int port, bool useSSL, int? maxResults, int? maxRetries, Dictionary<string, LdapAttributeTypes> attributeReturnTypes = null)
        {
            init(server, port, useSSL, maxResults, maxRetries, attributeReturnTypes);
        }

        public override string ToString()
        {
            if (this.UseSSL)
                return $"ldaps://{this.Server}:{this.Port}";
            else
                return $"ldap://{this.Server}:{this.Port}";
        }

        private void init(string server, int port, bool useSSL, int? maxResults, int? maxRetries, Dictionary<string, LdapAttributeTypes> attributeReturnTypes = null)
        {
            this.Server = server;
            this.Port = port;
            this.UseSSL = useSSL;
            if (maxResults != null)
                this.MaxResults = maxResults.Value;
            if (maxRetries != null)
                this.MaxRetries = maxRetries.Value;
            this.ReturnTypes = attributeReturnTypes;
            if (this.ReturnTypes == null)
                this.ReturnTypes = new Dictionary<string, LdapAttributeTypes>();

//            this.conn = new LdapConnection();

//            conn.SecureSocketLayer = this.UseSSL;
//            LdapSearchConstraints consts = conn.SearchConstraints;
//#pragma warning disable CS0618 // Type or member is obsolete
//            if (this.UseSSL)
//                conn.UserDefinedServerCertValidationDelegate += (sender, certificate, chain, errors) => true;
//#pragma warning restore CS0618 // Type or member is obsolete

            int attempts = 0;
            bool connected = false;

            Exception connError = null;
            while (attempts <= this.MaxRetries && !connected)
            {
                try
                {
                    this.Connect();
//                    consts = conn.SearchConstraints;
                    connected = true;
                }
                catch (Exception e)
                {
                    attempts++;
                    connError = e;
                    Console.WriteLine($"ERROR - Ldap Connection Failed.  {e.Message} - {e.ToString()}");
                }
            }

            if (!connected && connError != null)
            {
                Console.WriteLine("ERROR - Max Connection Attemps Reached.");
                throw connError;
            }
        }

        public void Connect()
        {
            conn = new LdapConnection();
            conn.Connect(this.Server, this.Port);
        }

        public void Disconnect()
        {
            conn = null;
        }

        public void Bind(LdapConfig config)
        {
            Bind(config.Username, config.Password);
        }

        public void Bind(string username, string password)
        {
            LdapCredential creds = new LdapCredential
            {
                UserName = username,
                Password = password,
            };
            conn.Bind(Native.LdapAuthType.Simple, creds);
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
                if (String.IsNullOrWhiteSpace(searchFilter))
                    throw new Exception("Search Filter Not Provided");

                if (searchBase == null)
                {
                    // Get Default Naming Context As Search Base
                    LdapEntry rootDSE = conn.GetRootDse();
                    searchBase = rootDSE.Dn;

                    SearchResultAttributeCollection rootAttributes = rootDSE.DirectoryAttributes;
                    if (rootAttributes.AttributeNames.Contains("defaultNamingContext"))
                        searchBase = rootAttributes["defaultNamingContext"].GetValue<string>();
                    else if (rootAttributes.AttributeNames.Contains("rootDomainNamingContext"))
                        searchBase = rootAttributes["rootDomainNamingContext"].GetValue<string>();
                }

                //LdapSearchResults results = null;
                //LdapSearchConstraints options = new LdapSearchConstraints();
                //options.TimeLimit = 0;
                //options.MaxResults = this.MaxResults;
                //options.ServerTimeLimit = 3600;
                //options.ReferralFollowing = true;

                if (attributes?.Length == 0)
                    attributes = new string[] { "" };

                //IList<LdapEntry> results =  conn.Search(searchBase, searchFilter, attributes);



                List<DirectoryEntry> results = new List<DirectoryEntry>();
                SearchRequest request = new SearchRequest(searchBase, searchFilter, Native.LdapSearchScope.LDAP_SCOPE_SUB, attributes);

                // Add Pagination Controller To Request
                PageResultRequestControl pageRequestControl = new PageResultRequestControl();       // Can Put Page Size Here, Leaving As Default
                request.Controls.Add(pageRequestControl);

                // Get Paged Response
                SearchResponse pagedResponse = (SearchResponse)conn.SendRequest(request);
                results.AddRange(pagedResponse.Entries);

                PageResultResponseControl pageResponseControl = null;

                while (true)
                {
                    // Get Pagination Controller Reponse
                    foreach (DirectoryControl control in pagedResponse.Controls)
                        if (control is PageResultResponseControl)
                        {
                            pageResponseControl = (PageResultResponseControl)control;
                            break;
                        }

                    // Check For More Records
                    if (pageResponseControl == null || pageResponseControl.Cookie.Length == 0)
                        break;

                    // Make Subsequent Request For More Records
                    pageRequestControl.Cookie = pageResponseControl.Cookie;
                    pagedResponse = (SearchResponse)conn.SendRequest(request);
                    results.AddRange(pagedResponse.Entries);

                }

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

        private LdapResponse ParseResults(List<DirectoryEntry> results)
        {
            LdapResponse response = new LdapResponse();
            response.Records = new List<LdapObject>();

            foreach (DirectoryEntry de in results)
            {
                try
                {
                    LdapEntry record = de.ToLdapEntry();

                    LdapObject rec = new LdapObject();
                    rec.DistinguishedName = record.Dn;
                    Console.WriteLine($"DN : {record.Dn}");

                    SearchResultAttributeCollection attributes =  record.DirectoryAttributes;

                    //LdapAttributeSet attributes = record.GetAttributeSet();
                    rec.Attributes = new Dictionary<string, object>();

                    if (attributes.Count > 0)
                    {
                        foreach (string key in attributes.AttributeNames)
                        {
                            DirectoryAttribute attribute = attributes[key];
                            Type rType = attribute.GetType();


                            // TODO : Check Types In Environment Variables
                            LdapAttributeTypes attrType = LdapAttributeTypes.Unknown;
                            if (this.ReturnTypes.ContainsKey(key))
                                attrType = this.ReturnTypes[key];
                            else if (DefaultTypes.ContainsKey(key))
                                attrType = DefaultTypes[key];

                            switch (attrType)
                            {
                                //case LdapAttributeTypes.Bytes:
                                //    string str = BitConverter.ToString(attribute.ByteValue);
                                //    str = str.Replace("-", "");
                                //    rec.Attributes.Add(key, "0x" + str);
                                //    break;
                                //case LdapAttributeTypes.BytesArray:
                                //    List<string> strs = new List<string>();
                                //    foreach (byte[] b in attribute.ByteValueArray)
                                //    {
                                //        string s = BitConverter.ToString(b);
                                //        strs.Add("0x" + s.Replace("-", ""));
                                //    }
                                //    rec.Attributes.Add(key, strs);
                                //    break;
                                //case LdapAttributeTypes.Guid:
                                //    rec.Attributes.Add(key, new Guid(attribute.ByteValue).ToString());
                                //    break;
                                //case LdapAttributeTypes.GuidArray:
                                //    List<string> guids = new List<string>();
                                //    foreach (byte[] guid in attribute.ByteValueArray)
                                //    {
                                //        string g = new Guid(guid).ToString();
                                //        guids.Add(g);
                                //    }
                                //    rec.Attributes.Add(key, guids);
                                //    break;
                                //case LdapAttributeTypes.Sid:
                                //    rec.Attributes.Add(key, SidUtils.ConvertByteToStringSid(attribute.ByteValue));
                                //    break;
                                //case LdapAttributeTypes.SidArray:
                                //    List<string> sids = new List<string>();
                                //    foreach (byte[] sid in attribute.ByteValueArray)
                                //    {
                                //        string s = SidUtils.ConvertByteToStringSid(sid);
                                //        sids.Add(s);
                                //    }
                                //    rec.Attributes.Add(key, sids);
                                //    break;
                                //case LdapAttributeTypes.String:
                                //    rec.Attributes.Add(key, attribute.StringValue);
                                //    break;
                                //case LdapAttributeTypes.StringArray:
                                //    rec.Attributes.Add(key, attribute.StringValueArray);
                                //    break;
                                //case LdapAttributeTypes.Number:
                                //    rec.Attributes.Add(key, long.Parse(attribute.StringValue));
                                //    break;
                                //case LdapAttributeTypes.NumberArray:
                                //    List<long> numbers = new List<long>();
                                //    foreach (string num in attribute.StringValueArray)
                                //    {
                                //        long l = long.Parse(num);
                                //        numbers.Add(l);
                                //    }
                                //    rec.Attributes.Add(key, numbers);
                                //    break;
                                //case LdapAttributeTypes.Boolean:
                                //    rec.Attributes.Add(key, bool.Parse(attribute.StringValue));
                                //    break;
                                //case LdapAttributeTypes.BooleanArray:
                                //    List<bool> bools = new List<bool>();
                                //    foreach (string bv in attribute.StringValueArray)
                                //    {
                                //        bool b = bool.Parse(bv);
                                //        bools.Add(b);
                                //    }
                                //    rec.Attributes.Add(key, bools);
                                //    break;
                                default:
                                    //string value = attribute.GetValue<string>();
                                    //object obj = null;

                                    //try { obj = int.Parse(value); } catch { }
                                    //if (obj == null)
                                    //    try { obj = bool.Parse(value); } catch { }
                                    //if (obj == null)
                                        //obj = value;

                                    //rec.Attributes.Add(key, obj);

                                    AddValueWithUnknownType(rec, key, attribute);
                                    break;

                            }

                            //if (attribute.ByteValueArray.Length > 1 && attrType != LdapAttributeTypes.BytesArray && attrType != LdapAttributeTypes.StringArray)
                            //    Console.WriteLine($"WARNING : Multi-Value Attribute [{attribute.Name}] Was Returned As A Single Value");
                        }
                    }


                    response.Records.Add(rec);
                }
                //catch (LdapReferralException lre)
                //{
                //    if (lre.ResultCode == 10)   // Referral
                //        continue;
                //    else
                //        throw lre;
                //}
                //catch (LdapException le)
                //{
                //    if (le.ResultCode == 4)     // Size Limit Exceeded
                //    {
                //        response.Message = "MaxResults Reached.  Results Are Incomplete.";
                //        response.ResultsIncomplete = true;
                //        break;
                //    }
                //    else
                //        throw le;
                //}
                catch (Exception e)
                {
                    throw e;
                }
            }

            return response;
        }

        private void AddValueWithUnknownType(LdapObject rec, string key, DirectoryAttribute attribute)
        {
            // TODO: Check for multi-values, GUID, SID, etc...
            string value = attribute.GetValue<string>();
            object obj = null;

            //try { obj = int.Parse(value); } catch { }
            //if (obj == null)
            //    try { obj = bool.Parse(value); } catch { }
            //if (obj == null)
                obj = value;

            rec.Attributes.Add(key, obj);
        }

        static public LdapResponse ReturnError(Exception e, LdapConfig config)
        {
            LdapResponse response = new LdapResponse();
            response.Success = false;
            response.Server = config.Server;
            response.Message = $"{e.Message} - {e.ToString()}";

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
