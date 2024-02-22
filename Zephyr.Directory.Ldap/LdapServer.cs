using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;


using System.Text;
using System.Collections;
using System.Collections.Generic;

using Novell.Directory.Ldap;
using Novell.Directory.Ldap.SearchExtensions;
using Novell.Directory.Ldap.Utilclass;
using Novell.Directory.Ldap.Controls;
using System.Threading;
using System.Linq;
using Zephyr.Directory.Ldap;
using System.Net.Cache;
using Microsoft.Extensions.Logging.Abstractions;
using System.Linq.Expressions;

namespace Zephyr.Directory.Ldap
{
    public partial class LdapServer
    {
        LdapConnection conn;

        public string Server { get; set; }
        public string TokenType { get; set; }
        public int Port { get; set; }
        public bool UseSSL { get; set; }
        public int MaxRetries { get; set; } = 0;
        public int MaxPageSize { get; set; } = 512;
        public bool FollowReferrals { get; set; } = false;
        public bool IgnoreWarnings { get; set; } = false;
        public Dictionary<string, LdapAttributeTypes> ReturnTypes { get; set; }

        public LdapServer(LdapConfig config)
        {
            init(config.Server, config.Port.Value, config.UseSSL.Value, config.MaxRetries, config.MaxPageSize, config.FollowReferrals, config.IgnoreWarnings, config.TokenType, config.AttributeTypes);
        }

        public LdapServer(string server, int port, bool useSSL, int? maxRetries, int? maxPageSize, bool? followReferrals, bool? ignoreWarnings, string token_type, Dictionary<string, LdapAttributeTypes> attributeReturnTypes = null)
        {
            init(server, port, useSSL, maxRetries, maxPageSize, followReferrals, ignoreWarnings, token_type, attributeReturnTypes);
        }

        public override string ToString()
        {
            if (this.UseSSL)
                return $"ldaps://{this.Server}:{this.Port}";
            else
                return $"ldap://{this.Server}:{this.Port}";
        }

        private void init(string server, int port, bool useSSL, int? maxRetries, int? maxPageSize,  bool? followReferrals, bool? ignoreWarnings, string tokenType, Dictionary<string, LdapAttributeTypes> attributeReturnTypes = null)
        {
            this.Server = server;
            this.Port = port;
            this.UseSSL = useSSL;
            if (maxRetries != null)
                this.MaxRetries = maxRetries.Value;
            if (maxPageSize != null)
                this.MaxPageSize = maxPageSize.Value;
            if (followReferrals != null)
                this.FollowReferrals = followReferrals.Value;
            if (ignoreWarnings != null)
                this.IgnoreWarnings = ignoreWarnings.Value;
            if (tokenType != null)
                this.TokenType = tokenType;
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

        public void test(List<ILdapSearchResults> results, string searchBase, int scope, string searchFilter, string[] attributes, bool flag, LdapSearchConstraints options){
            results.Add(conn.Search(searchBase, scope, searchFilter, attributes, flag, options));
        }
        public LdapResponse Search(LdapRequest request, string searchBase, string searchFilter, List<string> attributes, SearchScopeType? searchScope = null, int? maxResults = int.MaxValue, string nextTokenStr = null, List<UnionType> MultipleSearches = null)
        {
            return Search(request, searchBase, searchFilter, attributes?.ToArray(), searchScope, maxResults, nextTokenStr, MultipleSearches);
        }

        public Tuple<bool, byte[]> CheckForToken(List<ILdapSearchResults> results, List<LdapEntry> entries, byte[] nextToken_checker){
            bool Flag = true;
            ILdapSearchResults results2 = results[^1];
            while (results2.HasMore()){
                try{entries.Add(results2.Next());}
                catch (LdapReferralException lre){
                    if (lre.ResultCode == 10)   // Referral
                        continue;
                    else
                        throw lre;
                }
            }
            SimplePagedResultsControl pagedResponseControl_checker = null;
            foreach (LdapControl control in results2.ResponseControls)
            {
                if (control is SimplePagedResultsControl)
                {
                    pagedResponseControl_checker = (SimplePagedResultsControl)control;
                    break;
                }
            }
            if (pagedResponseControl_checker == null || pagedResponseControl_checker.Cookie.Length == 0){
                Flag = false;
                return Tuple.Create(Flag, nextToken_checker);
            }
            nextToken_checker = pagedResponseControl_checker.Cookie;
            return Tuple.Create(Flag, nextToken_checker);
        }
        public LdapResponse Search(LdapRequest request, string searchBase, string searchFilter, string[] attributes = null, SearchScopeType? searchScope = null, int? maxResults = int.MaxValue, string nextTokenStr = null, List<UnionType> MultipleSearches = null)
        {
            LdapResponse response = new LdapResponse();
            List<LdapEntry> entries = new List<LdapEntry>();
            string[] parsed_string = null;
            byte[] nextToken = null;
            int nextToken_client = 0;
            int Pick_up_Here = 1;
            try{
                try{
                    nextTokenStr =  Encoding.ASCII.GetString(Utils.Base64ToBytes(nextTokenStr));
                    parsed_string = nextTokenStr.Split("-");
                    nextToken_client = Int32.Parse(parsed_string[0]);
                    Pick_up_Here = Int32.Parse(parsed_string[1]);
                }
                catch{
                    parsed_string = nextTokenStr.Split("-");
                    nextToken = Utils.Base64ToBytes(parsed_string[0]);
                    Pick_up_Here = Int32.Parse(parsed_string[1]);
                }
                
            }
            catch{
                parsed_string = null;
                nextToken = Utils.Base64ToBytes(nextTokenStr);
                Pick_up_Here = 1;
            }
            byte[] nextToken_checker = Utils.Base64ToBytes(null);
            int iteration = 0;
            string PossibleNextToken = "";
            List<string> invalidAttributes = new List<string>();
            List<string> searchBase_list = new List<string>();
            List<string> searchFilter_list = new List<string>();

            try
            {
                if (String.IsNullOrWhiteSpace(searchFilter))
                    throw new Exception("Search Filter Not Provided");

                if (!conn.Connected)
                {
                    response.Message = $"Server {this} Is Not Connected.";
                    response.Success = false;
                    response.Status = StatusCode.Failure;
                }

                if (!conn.Bound)
                {
                    response.Message = $"Server {this} Is Not Bound.";
                    response.Success = false;
                    response.Status = StatusCode.Failure;
                }

                RootDseInfo rootDSE = conn.GetRootDseInfo();
                if (searchBase == null)
                    searchBase = rootDSE.DefaultNamingContext;


                // Validate Attributes Exist In Schema
                if (this.IgnoreWarnings == false && attributes != null)
                {
                    string schemaDN = conn.GetSchemaDn();
                    LdapSchema schema = conn.FetchSchema(schemaDN);

                    foreach (string attr in attributes)
                    {
                        try { LdapAttributeSchema attrSchema = schema.GetAttributeSchema(attr); }
                        catch { invalidAttributes.Add(attr);  }
                    }
                }

                if(MultipleSearches!=null){
                    searchBase_list.Add(searchBase);
                    searchFilter_list.Add(searchFilter);
                    for(int index =0; index < MultipleSearches.Count; index++){
                        UnionType i = MultipleSearches.ElementAt(index);
                        if(i.SearchBase == null && i.SearchValue != null){
                            i.SearchBase = searchBase;
                        }
                        else if(i.SearchBase != null && i.SearchValue == null){
                            i.SearchValue = searchFilter;
                        }
                        i.SearchValue = LdapUtils.CheckforError(request, i.SearchValue, i.SearchBase);
                        searchBase_list.Add(i.SearchBase);
                        searchFilter_list.Add(i.SearchValue);
                    }
                }

                // ILdapSearchResults results = null;
                List<ILdapSearchResults> results = new List<ILdapSearchResults>();
                LdapSearchConstraints options = new LdapSearchConstraints();
                options.TimeLimit = 0;
                options.MaxResults = 0;
                options.ServerTimeLimit = 3600;
                options.ReferralFollowing = this.FollowReferrals;

                while (true)
                {
                    int maxPageSize = this.MaxPageSize;

                    int maxSearchResults = int.MaxValue;
                    if (maxResults != null)
                        maxSearchResults = maxResults.Value;
                    
                    Console.WriteLine(maxSearchResults - entries.Count);
                    Console.WriteLine(this.MaxPageSize);
                    if (maxSearchResults - entries.Count < this.MaxPageSize)
                        maxPageSize = maxSearchResults - entries.Count;

                    if(TokenType == "Server"){
                        try{
                            if(nextTokenStr != $"AAAAAA==-{Pick_up_Here}"){
                                SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(maxPageSize, nextToken);
                                options.SetControls(pagedRequestControl);
                            }
                            else{
                            SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(maxPageSize, null);
                            options.SetControls(pagedRequestControl);
                            }
                        }
                        catch{
                            SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(maxPageSize, null);
                            options.SetControls(pagedRequestControl);
                        }
                    }
                    else{
                        if(nextTokenStr == null){
                            SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(maxPageSize, null);
                            options.SetControls(pagedRequestControl);
                        }
                        else{
                            SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(maxPageSize+nextToken_client, null);
                            options.SetControls(pagedRequestControl);
                        }
                    }
                    // No Attributes Will Be Returned
                    if (attributes?.Length == 0)
                        attributes = new string[] { "" };

                    int scope = LdapConnection.ScopeSub;
                    if (searchScope != null)
                        scope = (int)searchScope;
                    // If Pick up here is greater than 1, then pick up from Multiple Searches, else start with the original Search
                    // results.Add(conn.Search(searchBase, scope, searchFilter, attributes, false, options));
                    int currentRecords = 0;
                    if (TokenType == "Server"){
                        if(Pick_up_Here > 1){
                            results.Add(conn.Search(MultipleSearches[Pick_up_Here-2].SearchBase, scope, MultipleSearches[Pick_up_Here-2].SearchValue, attributes, false, options));
                        }
                        else{
                            results.Add(conn.Search(searchBase, scope, searchFilter, attributes, false, options));
                        }
                        bool Token_present = false;  
                        Token_present = CheckForToken(results, entries, nextToken_checker).Item1;
                        currentRecords = entries.Count;
                        if(MultipleSearches != null){
                            iteration = Pick_up_Here;
                            int recordsLeft = maxSearchResults - currentRecords;
                            if(!Token_present && recordsLeft != 0){
                                for(int index = Pick_up_Here-1; index < MultipleSearches.Count; index++){
                                    recordsLeft = maxSearchResults - currentRecords;
                                    LdapSearchConstraints options2 = new LdapSearchConstraints();
                                    SimplePagedResultsControl new_pagedRequestControl = new SimplePagedResultsControl(recordsLeft, nextToken);
                                    options2.SetControls(new_pagedRequestControl);
                                    if(recordsLeft <= maxSearchResults && currentRecords != maxSearchResults){
                                        var i = MultipleSearches.ElementAt(index);
                                        Thread testing_thread = new Thread(() => test(results, searchBase=i.SearchBase,scope, i.SearchValue, attributes, false, options2));
                                        testing_thread.Start();
                                        testing_thread.Join();
                                        iteration++;
                                        Token_present = CheckForToken(results, entries, nextToken_checker).Item1;
                                        currentRecords = entries.Count;
                                        // ILdapSearchResults result2 = results[^1];
                                        if(Token_present){
                                            break;
                                        }
                                    }
                                    else{ //When NextToken is Null Myriad errors out.
                                        // ILdapSearchResults result2 = results;
                                        Token_present = CheckForToken(results, entries, nextToken_checker).Item1;
                                        if(!Token_present){
                                            iteration++;
                                            nextToken_checker = BitConverter.GetBytes(0000);
                                            break;
                                        }
                                    }
                                    // Figure out a way to check if Next token is present.
                                }
                            }
                            else{
                                if(Token_present){
                                    nextToken_checker = CheckForToken(results, entries, nextToken_checker).Item2;
                                }
                                else{
                                    if(iteration-1 != MultipleSearches.Count){
                                        iteration++;
                                        nextToken_checker = BitConverter.GetBytes(0000);
                                    }
                                }
                            }
                        }
                    }
                    else{
                        //Nextoken will have to be an encoded number to keep the bytes array type
                        //Parse the string for Pick up here value and the actual next token.
                        string continue_token = "";
                        List<LdapEntry> entries_copy = new List<LdapEntry>();
                        if(Pick_up_Here > 1){
                            results.Add(conn.Search(MultipleSearches[Pick_up_Here-2].SearchBase, scope, MultipleSearches[Pick_up_Here-2].SearchValue, attributes, false, options));
                        }
                        else{
                            results.Add(conn.Search(searchBase, scope, searchFilter, attributes, false, options));
                        }
                        bool Token_present = false;
                        Token_present = CheckForToken(results, entries, nextToken_checker).Item1;
                        if(nextTokenStr != null){
                            // entries = entries.GetRange(nextToken_client+1, entries.Count);
                            for(int i =0; i < entries.Count; i++){
                                if(i < nextToken_client){
                                    continue;
                                }
                                entries_copy.Add(entries[i]);
                            }
                            entries = entries_copy;
                        }
                        currentRecords = entries.Count;
                        if(MultipleSearches != null){
                            iteration = Pick_up_Here;
                            int recordsLeft = maxSearchResults - currentRecords;
                            // try{recordsLeft = maxSearchResults+Int32.Parse(nextTokenStr) - currentRecords;}
                            // catch{recordsLeft = maxSearchResults - currentRecords;}
                            if(!Token_present && recordsLeft != 0){
                                string Records_gone_through = "";
                                for(int index = Pick_up_Here-1; index < MultipleSearches.Count; index++){
                                    // Now that we got the entries list issue fixed go ahead and implement recordsLeft.
                                    recordsLeft = maxSearchResults - currentRecords;
                                    if(recordsLeft <= maxSearchResults && currentRecords != maxSearchResults){
                                        var i = MultipleSearches.ElementAt(index);
                                        SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(recordsLeft, null);
                                        options.SetControls(pagedRequestControl);
                                        Thread testing_thread = new Thread(() => test(results, searchBase=i.SearchBase,scope, i.SearchValue, attributes, false, options));
                                        testing_thread.Start();
                                        testing_thread.Join();
                                        iteration++;
                                        Token_present = CheckForToken(results, entries, nextToken_checker).Item1;
                                        currentRecords = entries.Count;
                                        Records_gone_through = recordsLeft.ToString();
                                        if(Token_present){
                                            continue_token = $"-0{iteration}";
                                        }
                                        if(!Token_present && index == MultipleSearches.Count-1){
                                            PossibleNextToken = null;
                                            break;
                                        }
                                    }
                                    else{
                                        if(Token_present)
                                            continue_token = $"-0{iteration}";
                                        else{
                                            continue_token = $"-0{iteration+1}";
                                        }
                                        // try:
                                        //     PossibleNextToken = Records_gone_through + continueToken
                                        // except:
                                        //     PossibleNextToken = str(recordsLeft) + continueToken
                                        try{
                                            PossibleNextToken = string.Concat(Records_gone_through, continue_token);
                                        }
                                        catch{
                                            PossibleNextToken = string.Concat(recordsLeft.ToString(), continue_token);
                                        }
                                        break;
                                        
                                    }
                                    PossibleNextToken = String.Concat(recordsLeft.ToString(), continue_token);
                                }
                            }
                            else{
                                if(Token_present){
                                    continue_token = $"-0{Pick_up_Here}";
                                    PossibleNextToken = String.Concat((currentRecords+nextToken_client).ToString(), continue_token);
                                }
                                else{
                                    continue_token = $"-0{Pick_up_Here+1}";
                                    if(Pick_up_Here  > MultipleSearches.Count){
                                        PossibleNextToken = null;
                                    }
                                    else{
                                        PossibleNextToken = String.Concat(recordsLeft.ToString(), continue_token);
                                    }
                                }
                            }
                        }
                        else{
                            if(Token_present){
                               continue_token = $"-0{Pick_up_Here}";
                                PossibleNextToken = String.Concat((currentRecords+nextToken_client).ToString(), continue_token); 
                            }
                        }
                        Console.WriteLine();
                    }
                    for(int index =0; index < results.Count; index++){
                        ILdapSearchResults result = results[index];
                        while (result.HasMore())
                        {
                            try
                            {
                                entries.Add(result.Next());
                            }
                            catch (LdapReferralException lre)
                            {
                                if (lre.ResultCode == 10)   // Referral
                                    continue;
                                else
                                    throw lre;
                            }
                        }
                    }
                    // Get PageResponse
                    SimplePagedResultsControl pagedResponseControl = null;
                    foreach(var result in results){
                        foreach (LdapControl control in result.ResponseControls)
                        {
                            if (control is SimplePagedResultsControl)
                            {
                                pagedResponseControl = (SimplePagedResultsControl)control;
                                break;
                            }
                        }
                    }

                    if ((pagedResponseControl == null || pagedResponseControl.Cookie.Length == 0) && nextToken_checker == null && String.IsNullOrEmpty(PossibleNextToken))
                    {
                        nextToken = null;
                        break;
                    }
                    if(nextToken_checker != null){
                        nextToken = nextToken_checker;
                    }
                    else if(!String.IsNullOrEmpty(PossibleNextToken)){
                        nextToken = Encoding.ASCII.GetBytes(PossibleNextToken);
                    }
                    else{
                        nextToken = pagedResponseControl.Cookie;
                    }
                    // nextToken = pagedResponseControl.Cookie;
                    // Max Results Retrieved.
                    if (maxSearchResults <= entries.Count)
                        break;

                }

                response = ParseResults(entries);

                if (this.IgnoreWarnings == false && invalidAttributes.Count > 0)
                {
                    response.Status = StatusCode.SuccessWithWarnings;
                    if (invalidAttributes.Count == 1)
                        response.Message += $"Attribute [{String.Join(", ", invalidAttributes)}] Not Found In Schema.";
                    else
                        response.Message += $"Attributes [{String.Join(", ", invalidAttributes)}] Not Found In Schema.";
                }

                // If there are still more records, pass back the Next Token in the response.
                if (nextToken != null && nextToken.Length > 0)
                    if (iteration >= 1 && string.IsNullOrEmpty(PossibleNextToken))
                        response.NextToken = String.Concat(Utils.BytesToBase64(nextToken), String.Concat("-", iteration.ToString()));
                    else
                        response.NextToken = Utils.BytesToBase64(nextToken);
            }
            catch (Exception e)
            {
                response.Message = e.Message;
                response.Success = false;
                response.Status = StatusCode.Failure;
            }

            response.Server = this.ToString();
            if(MultipleSearches != null){
                response.SearchBases = searchBase_list;
                response.SearchFilters = searchFilter_list;
            }
            else{
                response.SearchBase = searchBase;
                response.SearchFilter = searchFilter;
            }

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
                        response.Message = $"Page Size Limit Exceeded.  Current Value is ${this.MaxPageSize}.  Please Increase This Value.";
                        break;
                    }
                    else
                        throw le;
                }
            }

            response.TotalRecords = entries.Count;

            return response;
        }

        private void AddValueWithUnknownType(LdapObject rec, string key, LdapAttribute attribute)
        {
            string[] values = attribute.StringValueArray;

            if (values.Length > 1)
                rec.Attributes.Add(key, values);
            else
                rec.Attributes.Add(key, values[0]);
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
