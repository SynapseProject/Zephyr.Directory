using Amazon.Lambda.APIGatewayEvents;
using System;
using System.Dynamic;
using System.Collections.Generic;
using System.IO;
using System.Globalization;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using System.Linq;
using System.Xml.Serialization;
using System.Xml.Linq;
using System.Xml;
using CsvHelper;
using CsvHelper.Configuration;
using Zephyr.Crypto;

using Zephyr.Directory.Ldap;
using System.Text;
using System.Net.Http;
using System.Data;
using Novell.Directory.Ldap.Utilclass;
using CsvHelper.Expressions;
using System.Runtime.CompilerServices;
using System.Linq.Expressions;
using YamlDotNet.Serialization;
using Newtonsoft.Json.Linq;

namespace Zephyr.Directory
{
    class Program
    {
        public static string parse_data(LdapObject data,List<string> headers){ 
            List<object> csv_list = new List<object>();
            string csv_string = null;
            csv_list.Add(data.DistinguishedName);
            csv_string = string.Join(",", csv_list);
            foreach(KeyValuePair<string, dynamic> pair in data.Attributes){
                Console.WriteLine(pair.Value.GetType());
                if(pair.Value is string[] || pair.Value is List<string> || pair.Value is int[] || pair.Value is List<int>){
                    string array_string = "[ ";
                    array_string += string.Join(", ", pair.Value);
                    array_string += " ]";
                    csv_list.Add(array_string);
                }
                else{
                    Console.WriteLine();
                    csv_list.Add(pair.Value);
                }
                csv_string = string.Join(",", csv_list);
            }
            
            return csv_string;
        }
        public static dynamic OutputConverter(LdapResponse response, OutputType? type){
            //string xmlString = null;
            dynamic OutputObject = null;
            if(type == OutputType.Json){
                string test = JsonTools.Serialize(response, true);
                OutputObject = test;
            }
            // else if(type == OutputType.XML){
            //     XNode node = JsonConvert.DeserializeXNode(JsonTools.Serialize(response, true), "Root");
            //     OutputObject = node;
            // }
            else if(type == OutputType.YAML){
                // dynamic expConverter = new ExpandoObject();
                // string json = JsonTools.Serialize(response, false);
                // dynamic deserializedObject = JsonConvert.DeserializeObject<LdapResponse>(json, expConverter);
                // var serializer = new YamlDotNet.Serialization.Serializer();
                // var yaml = serializer.Serialize(deserializedObject);
                ////////////////////////////////////////////
                // var serializer = new Serializer();
                // var yaml = new StringBuilder();
                // await using var textWriter = new StringWriter(yaml);
                // serializer.Serialize(textWriter, input, typeof(T));
                // Console.WriteLine(yaml.ToString());
                //////////////////////////////////////////////
                var serializer = new SerializerBuilder().ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull).Build();
                var yaml = serializer.Serialize(response);
                OutputObject = yaml;
            }
            else{
                List<LdapObject> records = response.Records;
                List<string> column_headers = new List<string>();
                column_headers.Add("dn");
                foreach(KeyValuePair<string,object> pair in records[0].Attributes)
                    column_headers.Add(pair.Key.ToString());
                string s = string.Join(",", column_headers) + Environment.NewLine;
                foreach (LdapObject record in records){
                    string ss = parse_data(record, column_headers);
                    s += $"{ss}{Environment.NewLine}";
                }
                OutputObject = s;
            }
            return OutputObject;
        }
        static void Main(string[] args)
        {
            string content = File.ReadAllText(@"../../../TestFiles/myriad.json");
            LdapRequest request = JsonTools.Deserialize<LdapRequest>(content);
            // JObject o1 = JObject.Parse(File.ReadAllText(@"../../../TestFiles/myriad.json"));
            // LdapRequest request = JsonTools.Deserialize<LdapRequest>(o1["body"].ToString());
            Console.WriteLine(JsonTools.Serialize(request, true));

            bool isPing = request.Ping.HasValue;
            dynamic output_data = null;

            LdapResponse response = new LdapResponse();
            LdapConfig test_config = LdapUtils.ApplyDefaulsAndValidate(request.Config);
            if(request.Config.batch == true && request.Config.retrieval == false){
                DynamoDBTools dynamo = new DynamoDBTools();
                var new_response = dynamo.invokeLambda(content);
                output_data = new_response;
            }
            else if(request.Config.retrieval == true && request.Config.batch == false){
                DynamoDBTools dynamo = new DynamoDBTools();
                LdapResponse new_response = new LdapResponse();
                new_response = dynamo.Batch_Retrieval(request);
                output_data = new_response;
                Console.WriteLine("Retrieve from DynamoDB");
            }
            else{
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
                        if(request.Config.TokenType == "Server" || request.Config.TokenType == "Client"){
                            try{
                                if(request.Config.batch == true && request.Config.retrieval == true){
                                    DynamoDBTools db = new DynamoDBTools();
                                    db.add_entry(request);
                                }
                            }
                            catch(Exception e){
                                Console.WriteLine(e);
                            }
                            response = ldap.Search(request, request.SearchBase, searchFilter, request.Attributes, request.SearchScope, request.MaxResults, request.NextToken, request.Union);
                    
                        }
                        else{
                            throw new FormatException("Warning: TokenType must be set to Server or Client");
                        }    
                        ldap.Disconnect();
                        output_data = OutputConverter(response, request.Config.outputType);
                    }
                    catch (Exception e)
                    {
                        response = LdapServer.ReturnError(e, request.Config);
                        output_data = response;
                    }
                    // if(request.Config.Output == OutputType.XML){
                    //     Dictionary<string, string> headers = new Dictionary<string, string> { { "Content-Type", "application/xml"}};
                    //     string xmlstring = output_data.ToString();
                    //     return Dictionary<string, string> test = new Dictionary<string,string>
                    // }
                }
                Console.WriteLine(JsonTools.Serialize(response, true));
                try{
                    if(request.Config.batch == true && request.Config.retrieval==true){
                        DynamoDBTools db = new DynamoDBTools();
                        db.update_entry(response, request);
                    }
                }
                catch{
                    Console.WriteLine("");
                }
                Console.WriteLine(output_data);
            }
            Console.WriteLine(JsonTools.Serialize(output_data, true));
        }
    }
}
