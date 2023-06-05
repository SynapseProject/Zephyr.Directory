using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


using System.Text;
using System.Collections;
using System.Collections.Generic;

using Novell.Directory.Ldap;
using Novell.Directory.Ldap.SearchExtensions;
using Novell.Directory.Ldap.Utilclass;
using Novell.Directory.Ldap.Controls;

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
        public int MaxPageSize { get; set; } = 512;
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

            this.conn = new LdapConnection();

            conn.SecureSocketLayer = this.UseSSL;
            LdapSearchConstraints consts = conn.SearchConstraints;
#pragma warning disable CS0618 // Type or member is obsolete
            if (this.UseSSL)
                conn.UserDefinedServerCertValidationDelegate += (sender, certificate, chain, errors) => true;
#pragma warning restore CS0618 // Type or member is obsolete

            int attempts = 0;

            Exception connError = null;
            while (attempts <= this.MaxRetries && !conn.Connected)
            {
                try
                {
                    this.Connect();
                    consts = conn.SearchConstraints;
                }
                catch (Exception e)
                {
                    attempts++;
                    connError = e;
                    Console.WriteLine($"ERROR - Ldap Connection Failed.  {e.Message} - {e.ToString()}");
                }
            }

            if (!conn.Connected && connError != null)
            {
                Console.WriteLine("ERROR - Max Connection Attemps Reached.");
                throw connError;
            }
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

        public LdapResponse Search(string searchBase, string searchFilter, List<string> attributes, string nextTokenStr = null)
        {
            return Search(searchBase, searchFilter, attributes?.ToArray(), nextTokenStr);
        }

        public LdapResponse Search(string searchBase, string searchFilter, string[] attributes = null, string nextTokenStr = null)
        {
            LdapResponse response = new LdapResponse();
            List<LdapEntry> entries = new List<LdapEntry>();
            byte[] nextToken = Utils.Base64ToBytes(nextTokenStr);
            int resultsRemaining = this.MaxResults;

            try
            {
                if (String.IsNullOrWhiteSpace(searchFilter))
                    throw new Exception("Search Filter Not Provided");

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
                LdapSearchConstraints options = new LdapSearchConstraints();
                options.TimeLimit = 0;
                options.MaxResults = 0;
                options.ServerTimeLimit = 3600;
                //options.ReferralFollowing = true;

                // TODO: Add Pagination Of Results

                while (true)
                {
                    SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(this.MaxPageSize, nextToken);
                    options.SetControls(pagedRequestControl);

                    // No Attributes Will Be Returned
                    if (attributes?.Length == 0)
                        attributes = new string[] { "" };

                    results = (LdapSearchResults)conn.Search(searchBase, LdapConnection.ScopeSub, searchFilter, attributes, false, options);
                    while (results.HasMore())
                        entries.Add(results.Next());

                    // Get PageResponse
                    SimplePagedResultsControl pagedResponseControl = null;
                    foreach (LdapControl control in results.ResponseControls)
                    {
                        if (control is SimplePagedResultsControl)
                        {
                            pagedResponseControl = (SimplePagedResultsControl)control;
                            break;
                        }
                    }

                    if (pagedResponseControl == null || pagedResponseControl.Cookie.Length == 0)
                    {
                        nextToken = null;
                        break;
                    }

                    nextToken = pagedResponseControl.Cookie;
                    Console.WriteLine($">> Total Records Found : {entries.Count}");

                }

                response = ParseResults(entries);

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

        private LdapResponse ParseResults(List<LdapEntry> entries)
        {
            LdapResponse response = new LdapResponse();
            response.Records = new List<LdapObject>();

            foreach (LdapEntry record in entries)
            {
                try
                {
                    LdapObject rec = new LdapObject();
                    rec.DistinguishedName = record.Dn;

                    LdapAttributeSet attributes = record.GetAttributeSet();
                    rec.Attributes = new Dictionary<string, object>();

                    foreach (string key in attributes.Keys)
                    {
                        LdapAttribute attribute = attributes[key];

                        // TODO : Check Types In Environment Variables
                        LdapAttributeTypes attrType = LdapAttributeTypes.Unknown;
                        if (this.ReturnTypes.ContainsKey(key))
                            attrType = this.ReturnTypes[key];
                        else if (DefaultTypes.ContainsKey(key))
                            attrType = DefaultTypes[key];

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
                            case LdapAttributeTypes.GuidArray:
                                List<string> guids = new List<string>();
                                foreach (byte[] guid in attribute.ByteValueArray)
                                {
                                    string g = new Guid(guid).ToString();
                                    guids.Add(g);
                                }
                                rec.Attributes.Add(key, guids);
                                break;
                            case LdapAttributeTypes.Sid:
                                rec.Attributes.Add(key, SidUtils.ConvertByteToStringSid(attribute.ByteValue));
                                break;
                            case LdapAttributeTypes.SidArray:
                                List<string> sids = new List<string>();
                                foreach (byte[] sid in attribute.ByteValueArray)
                                {
                                    string s = SidUtils.ConvertByteToStringSid(sid);
                                    sids.Add(s);
                                }
                                rec.Attributes.Add(key, sids);
                                break;
                            case LdapAttributeTypes.String:
                                rec.Attributes.Add(key, attribute.StringValue);
                                break;
                            case LdapAttributeTypes.StringArray:
                                rec.Attributes.Add(key, attribute.StringValueArray);
                                break;
                            case LdapAttributeTypes.Number:
                                rec.Attributes.Add(key, long.Parse(attribute.StringValue));
                                break;
                            case LdapAttributeTypes.NumberArray:
                                List<long> numbers = new List<long>();
                                foreach (string num in attribute.StringValueArray)
                                {
                                    long l = long.Parse(num);
                                    numbers.Add(l);
                                }
                                rec.Attributes.Add(key, numbers);
                                break;
                            case LdapAttributeTypes.Boolean:
                                rec.Attributes.Add(key, bool.Parse(attribute.StringValue));
                                break;
                            case LdapAttributeTypes.BooleanArray:
                                List<bool> bools = new List<bool>();
                                foreach (string bv in attribute.StringValueArray)
                                {
                                    bool b = bool.Parse(bv);
                                    bools.Add(b);
                                }
                                rec.Attributes.Add(key, bools);
                                break;
                            default:
                                AddValueWithUnknownType(rec, key, attribute);
                                break;

                        }

                        if (attribute.ByteValueArray.Length > 1 && attrType != LdapAttributeTypes.BytesArray && attrType != LdapAttributeTypes.StringArray)
                            Console.WriteLine($"WARNING : Multi-Value Attribute [{attribute.Name}] Was Returned As A Single Value");
                    }


                    response.Records.Add(rec);
                }
                catch (LdapReferralException lre)
                {
                    if (lre.ResultCode == 10)   // Referral
                        continue;
                    else
                        throw lre;
                }
                catch (LdapException le)
                {
                    if (le.ResultCode == 4)     // Size Limit Exceeded
                    {
                        response.Message = "Page Size Limit Exceeded.";
                        break;
                    }
                    else
                        throw le;
                }
            }

            return response;
        }

        private void AddValueWithUnknownType(LdapObject rec, string key, LdapAttribute attribute)
        {
            // TODO: Check for multi-values, GUID, SID, etc...
            string value = attribute.StringValue;
            object obj = null;

            try { obj = int.Parse(value); } catch { }
            if (obj == null)
                try { obj = bool.Parse(value); } catch { }
            if (obj == null)
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
