﻿using System;
using System.Collections.Generic;

using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;

using Newtonsoft.Json;
using System.Linq;
using System.Xml.Serialization;
using System.Xml.Linq;
using System.Xml;
using CsvHelper;
using CsvHelper.Configuration;
using YamlDotNet.Serialization;
using Zephyr.Crypto;
using Newtonsoft.Json.Linq;

using Zephyr.Crypto;
using Zephyr.Directory.Ldap;

// Allows Lambda Function's JSON Input to be converted into a .NET class
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]
namespace Zephyr.Directory.Aws
{
    public class Ldap
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
            string xmlString = null;
            dynamic OutputObject = null;
            if(type == OutputType.Json){
                OutputObject = response;
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
                // OutputObject = yaml;
                //////////////////////////////////////////////
                // var response_obj = new APIGatewayProxyResponse{
                //     Body = yaml,
                //     Headers = new Dictionary<string, string> { { "Content-Type", "application/yaml"} }
                // };
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
        public static dynamic ProcessRequest(LdapRequest request, ILambdaContext ctx)
        {   
            bool isPing = request.Ping.HasValue;
            dynamic output_data = null;
            bool isEncryptionRequest = request.Crypto?.Text != null;

            LdapResponse response = new LdapResponse();
            LdapConfig test_config = LdapUtils.ApplyDefaulsAndValidate(request.Config);
           if(request.Config.batch == true && request.Config.retrieval == false){
                Console.WriteLine("In Batch");
                DynamoDBTools dynamo = new DynamoDBTools();
                LdapBatchResponse new_response = new LdapBatchResponse();
                string content = JsonTools.Serialize(request,true);
                new_response = dynamo.invokeLambda(content);
                Console.WriteLine("Invoke Function");
                return new_response;
            }
            else if(request.Config.retrieval == true && request.Config.batch == false){
                Console.WriteLine("Retrieve from DynamoDB");
                DynamoDBTools dynamo = new DynamoDBTools();
                LdapResponse new_response = new LdapResponse();
                new_response = dynamo.Batch_Retrieval(request);
                output_data = new_response;
            }
            else{
                if (!isEncryptionRequest && !isPing)
                    Console.WriteLine("REQUEST - " + JsonTools.Serialize(request, false));

                if (isEncryptionRequest)
                {
                    LdapCrypto crypto = LdapUtils.ApplyDefaulsAndValidate(request.Crypto);
                    response.Message = Rijndael.Encrypt(crypto.Text, crypto.PassPhrase, crypto.SaltValue, crypto.InitVector);
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
                        if(request.Config.tokenType == "Server" || request.Config.tokenType == "Client"){
                            try{
                                if(request.Config.batch == true && request.Config.retrieval == true){
                                    Console.WriteLine("Adding Entry");
                                    DynamoDBTools db = new DynamoDBTools();
                                    db.add_entry(request);
                                }
                            }
                            catch{
                                Console.WriteLine("");
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
                    }
                    try{
                        if(request.Config.batch == true && request.Config.retrieval == true){
                            DynamoDBTools db = new DynamoDBTools();
                            db.update_entry(response, request);
                        }
                    }
                    catch{
                        Console.WriteLine("");
                    }
                }
            }
            if (!isEncryptionRequest && !isPing)
                Console.WriteLine("RESPONSE - " + JsonTools.Serialize(response, false)); 
            return output_data;
        }
    }
}
