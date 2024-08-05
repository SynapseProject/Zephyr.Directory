using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;

using Amazon.DynamoDBv2.Model;

using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Serialization;

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
using System.Xml.Linq;
using Newtonsoft.Json;
using System.IO;
using System.ComponentModel;
using System.Net;
using CsvHelper;

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
            // This function checks for a PagedSearch Cookie Value
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

        private void MultipleSearchesValidation(LdapRequest request, string searchBase, string searchFilter, List<string> searchBase_list, List<string> searchFilter_list, List<UnionType> MultipleSearches){
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

        private void getControls(string nextTokenStr, byte[] nextToken, int nextToken_client, int Pick_up_Here, int maxPageSize, LdapSearchConstraints options){
            if(TokenType == "Server"){
                try{
                    if(nextTokenStr != $"AAAAAA==-{Pick_up_Here}" && nextToken != null){
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
                // Initial Page Search for Client Based Token
                if(nextTokenStr == null && nextToken == null){
                    SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(maxPageSize, null);
                    options.SetControls(pagedRequestControl);
                }
                else{
                    try{
                        // This is the options MyriAD will use when MaxResults havent been achieved, aka multiple Iterations of the while loop
                        SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(maxPageSize+nextToken_client, nextToken);
                        options.SetControls(pagedRequestControl);
                    }
                    catch{
                        SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(maxPageSize+nextToken_client, null);
                        options.SetControls(pagedRequestControl);
                    }
                }
            }
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
                    // Client Based Next Token Parsing
                    nextTokenStr =  Encoding.ASCII.GetString(Utils.Base64ToBytes(nextTokenStr));
                    parsed_string = nextTokenStr.Split("-");
                    nextToken_client = Int32.Parse(parsed_string[0]);
                    Pick_up_Here = Int32.Parse(parsed_string[1]);
                }
                catch{
                    // Server Based Next Token Parsing
                    parsed_string = nextTokenStr.Split("-");
                    nextToken = Utils.Base64ToBytes(parsed_string[0]);
                    Pick_up_Here = Int32.Parse(parsed_string[1]);
                    if(Pick_up_Here == 0){
                        Pick_up_Here = 1;
                    }
                }
                
            }
            catch{ 
                // If NextTokenStr is set to None
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
                    // Validate each entry in the Union Property
                    MultipleSearchesValidation(request,searchBase,searchFilter,searchBase_list,searchFilter_list,MultipleSearches);
                }

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
                    
                    if (maxSearchResults - entries.Count < this.MaxPageSize)
                        maxPageSize = maxSearchResults - entries.Count;
                    //Get Controls for the LDAP Search
                    getControls(nextTokenStr,nextToken,nextToken_client,Pick_up_Here, maxPageSize, options);
                    // No Attributes Will Be Returned
                    if (attributes?.Length == 0)
                        attributes = new string[] { "" };

                    int scope = LdapConnection.ScopeSub;
                    if (searchScope != null)
                        scope = (int)searchScope;
                    int currentRecords = 0;
                    if (TokenType == "Server"){
                        // Searching process for Server Based Token
                        // Pick_up_Here is used to determine where the previous search finished, if Pick_up_Here is > 1 that means that the search finished in a Multiple Searches Entry
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
                                    // The LDAP SearchConstraints have to updated to take into consideration the entries that have been collected
                                    LdapSearchConstraints options2 = new LdapSearchConstraints();
                                    SimplePagedResultsControl new_pagedRequestControl = new SimplePagedResultsControl(recordsLeft, nextToken);
                                    options2.SetControls(new_pagedRequestControl);
                                    if(recordsLeft <= maxSearchResults && currentRecords != maxSearchResults){
                                        var i = MultipleSearches.ElementAt(index);
                                        // Multi Threading for Multiple Searches, the new entries will be added to the results list
                                        Thread testing_thread = new Thread(() => test(results, searchBase=i.SearchBase,scope, i.SearchValue, attributes, false, options2));
                                        testing_thread.Start();
                                        testing_thread.Join();
                                        iteration++;
                                        Token_present = CheckForToken(results, entries, nextToken_checker).Item1;
                                        currentRecords = entries.Count;
                                        if(Token_present){
                                            // Token is present, with a token being present that means that maxResults has been met.
                                            break;
                                        }
                                    }
                                    else{
                                        Token_present = CheckForToken(results, entries, nextToken_checker).Item1;
                                        if(!Token_present){ // Code will only go in here if Records Left is 0 and theres another Multiple Searces entry
                                            iteration++;
                                            nextToken_checker = BitConverter.GetBytes(0000);
                                            break;
                                        }
                                    }
                                }
                            }
                            else{
                                if(Token_present){
                                    nextToken_checker = CheckForToken(results, entries, nextToken_checker).Item2;
                                }
                                else{
                                    if(iteration-1 != MultipleSearches.Count){ // Checker to make sure iteration is not iterating the last entry in the "union" List
                                        iteration++;
                                        nextToken_checker = BitConverter.GetBytes(0000);
                                    }
                                }
                            }
                        }
                    }
                    else{
                        // Searching process for Client Based Token
                        string continue_token = "";
                        List<LdapEntry> entries_copy = new List<LdapEntry>();
                        // Pick_up_Here is used to determine where the previous search finished, if Pick_up_Here is > 1 that means that the search finished in a 
                        // Multiple Searches Entry
                        if(Pick_up_Here > 1){
                            results.Add(conn.Search(MultipleSearches[Pick_up_Here-2].SearchBase, scope, MultipleSearches[Pick_up_Here-2].SearchValue, attributes, false, options));
                        }
                        else{
                            results.Add(conn.Search(searchBase, scope, searchFilter, attributes, false, options));
                        }
                        bool Token_present = false;
                        Token_present = CheckForToken(results, entries, nextToken_checker).Item1;
                        currentRecords = entries.Count;
                        if(nextTokenStr != null){
                            currentRecords = 0;
                            // This for loop is used to determine the count of the records gathered during the previous search
                            for(int i =0; i < entries.Count; i++){
                                if(i < nextToken_client){
                                    continue;
                                }
                                entries_copy.Add(entries[i]);
                            }
                            if (entries_copy.Count > 0){
                                entries = entries_copy;
                                currentRecords = entries_copy.Count;
                            }
                        }
                        if(MultipleSearches != null){
                            iteration = Pick_up_Here;
                            int recordsLeft = maxSearchResults - currentRecords;
                            if(!Token_present && recordsLeft != 0){
                                string Records_gone_through = "";
                                for(int index = Pick_up_Here-1; index < MultipleSearches.Count; index++){
                                    // Now that we got the entries list issue fixed go ahead and implement recordsLeft.
                                    recordsLeft = maxSearchResults - currentRecords;
                                    if(recordsLeft <= maxSearchResults && currentRecords != maxSearchResults){
                                        var i = MultipleSearches.ElementAt(index);
                                        // The LDAP SearchConstraints have to updated to take into consideration the entries that have been collected
                                        SimplePagedResultsControl pagedRequestControl = new SimplePagedResultsControl(recordsLeft, null);
                                        options.SetControls(pagedRequestControl);
                                        // Multi Threading for Multiple Searches, the new entries will be added to the results list
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
                                            // No Token is present and index is at the last entry. In other words the searxch is finished
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
                            // Union is not present, meaning its just an ordinary search
                            if(Token_present){
                               continue_token = $"-0{Pick_up_Here}";
                                PossibleNextToken = String.Concat((currentRecords+nextToken_client).ToString(), continue_token); 
                            }
                        }
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
                    else if(!String.IsNullOrEmpty(PossibleNextToken) && currentRecords == maxResults){
                        nextToken = Encoding.ASCII.GetBytes(PossibleNextToken);
                    }
                    else{
                        nextToken = pagedResponseControl.Cookie;
                    }
                    // Max Results Retrieved.
                    if (maxSearchResults <= currentRecords)
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
                    else{
                        if(TokenType == "Client")
                            response.NextToken = Utils.BytesToBase64(nextToken);
                        else
                            response.NextToken = String.Concat(Utils.BytesToBase64(nextToken), String.Concat("-", iteration.ToString()));
                    }
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

        public static void get_Known_attributes(string Key, AttributeValue value){
            bool key_checker = DefaultTypes.ContainsKey(Key);
            if(key_checker){
                string value_type = DefaultTypes[Key].ToString();
                if(value_type.Contains("Array")){

                }
                else{
                    
                }
            }
        }
    }
}
