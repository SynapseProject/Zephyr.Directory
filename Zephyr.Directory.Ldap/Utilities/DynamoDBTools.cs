using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Amazon;
using Amazon.Runtime;
using System.Collections.Generic;
using Amazon.Lambda;
using Amazon.Lambda.Model;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DocumentModel;
using Newtonsoft.Json;
using System.Reflection;
using Newtonsoft.Json.Linq;
using Amazon.DynamoDBv2.Model;
using System.Runtime.CompilerServices;
using System.Data;
using System.Threading.Tasks.Dataflow;
using System.Globalization;
using System.Linq;
using Amazon.DynamoDBv2.DataModel;
namespace Zephyr.Directory.Ldap
{
    public class Payload{
        public string jobID{get; set;}
        public string recordsID{get; set;}
        public string body{get; set;}
        public bool batch{get; set;}
        public string Timestamp{get; set;}
        public int expireAt{get; set;}
        public Payload(string JobID, string Rec_ID, string body, string time, int epoch){
            this.jobID = JobID;
            this.recordsID = Rec_ID;
            this.body = body;
            this.Timestamp = time;
            this.expireAt = epoch;
        }
    }
    public class Entry_Records{
        public string RecordsID{ get; set;}
        public int RecordNumber { get; set;}
        public LdapObject Record { get; set;}
        public string Timestamp { get; set;}
        public int expireAt { get; set;}
        public Entry_Records(string recordsID, int num, dynamic record, string time, int expire){
            this.RecordsID = recordsID;
            this.RecordNumber = num;
            this.Record = record;
            this.Timestamp = time;
            this.expireAt= expire;
        }
    }
    public class Entry{
        public string JobID{get; set;}
        public string Timestamp{get; set;}
        public int TotalRecords{get; set;}
        public string recordsID{get; set;}
        public string Completed{get; set;}
        public int expireAt{get; set;}

        public Entry(){
            JobID = "";
            Timestamp = "";
            TotalRecords = 0;
            recordsID = "";
            Completed = "";
            expireAt = 0;
        }
    }
    public class DynamoDBTools{
        public RegionEndpoint Region { get; internal set; }
        public string RegionName
        {
            get { return Region.DisplayName; }
            set { Region = RegionEndpoint.GetBySystemName("us-east-2"); }
        }
        public string DefaultReporter { get; set; }
        private string RequestsTable = System.Environment.GetEnvironmentVariable("Myriad_request_table");
        private string RecordsTable = System.Environment.GetEnvironmentVariable("Myriad_records_table");
        private AmazonDynamoDBClient client;
        private AmazonLambdaClient lambdaClient;


        public DynamoDBTools(){
            RegionName = GetVariable("AWS_REGION", RegionEndpoint.USEast2.DisplayName);
            DefaultReporter = GetVariable("Syntinel_DefaultReporter", "_default");
            client = new AmazonDynamoDBClient(RegionEndpoint.USEast2);
            lambdaClient = new AmazonLambdaClient(RegionEndpoint.USEast2);
        }
        private static string GetVariable(string variable, string defaultValue = null)
        {
            string value = System.Environment.GetEnvironmentVariable(variable);
            if (String.IsNullOrWhiteSpace(value))
                return defaultValue;
            else
                return value;
        }
        public void add_entry(LdapRequest request){
            Console.WriteLine(RequestsTable);
            Console.WriteLine(client);
            Table Request = Table.LoadTable(client, RequestsTable);

            Entry entry_to_add = new Entry();
            entry_to_add.JobID = request.jobID;
            entry_to_add.Completed = "In Progress";
            entry_to_add.recordsID = request.recordsID;
            entry_to_add.TotalRecords = 0;
            entry_to_add.Timestamp = request.Timestamp;
            entry_to_add.expireAt = request.expireAt;
            Console.WriteLine(entry_to_add.JobID, entry_to_add.recordsID);

            string jsonString = System.Text.Json.JsonSerializer.Serialize(entry_to_add);
            Console.WriteLine(jsonString);
            Document doc = Document.FromJson(jsonString);
            var task = Request.PutItemAsync(doc);
            // Console.WriteLine(task.Result);
        }
        public async Task<string> Invoke(string data){
            InvokeRequest request = new InvokeRequest
            {
                FunctionName = "myriad-core",
                Payload = data
            };
            var test = await lambdaClient.InvokeAsync(request);
            if (test != null){
                using (var sr = new StreamReader(test.Payload)){
                    return await sr.ReadToEndAsync();
                }
            }
            return string.Empty;  
        }
        public LdapBatchResponse invokeLambda(LdapRequest request_obj){
            string request_body = JsonTools.Serialize(request_obj,true);
            Guid jobID_uuid = Guid.NewGuid();
            Guid Records_uuid = Guid.NewGuid();
            string jobID_uuid2 = jobID_uuid.ToString();
            string Records_uuid2 = Records_uuid.ToString().Substring(0, 6);
            TimeSpan t = DateTime.UtcNow - new DateTime(1970, 1, 1);

            Payload Payload_input = new Payload(jobID_uuid2, Records_uuid2, request_body, DateTime.Now.ToString(), (int)t.TotalSeconds + int.Parse(System.Environment.GetEnvironmentVariable("TimeToLive"))*24*60*60);
            LdapRequest req = JsonTools.Deserialize<LdapRequest>(request_body);
            req.jobID = jobID_uuid2;
            req.recordsID = Records_uuid2;
            req.Timestamp = DateTime.Now.ToString();
            req.expireAt = (int)t.TotalSeconds + int.Parse(System.Environment.GetEnvironmentVariable("TimeToLive"))*24*60*60;
            req.Config.batch = true;
            req.Config.retrieval = true;

            string requestStr = JsonConvert.SerializeObject(req);
            Console.WriteLine(requestStr);
            InvokeRequest request = new InvokeRequest
            {
                FunctionName = "myriad-core",
                InvocationType = InvocationType.Event,
                LogType = "Tail",
                Payload = requestStr
            };
            var test = lambdaClient.InvokeAsync(request);
            Console.WriteLine(test.Result.Payload);
            LdapBatchResponse response = new LdapBatchResponse();
            response.jobID = Payload_input.jobID;
            response.recordsID = Payload_input.recordsID;
            return response;
        }

        private void write_to_records_Table(List<LdapObject> records, LdapRequest request){
            List<Entry_Records> dbRecords = new List<Entry_Records>();
            if (records != null){
                for(int i = 0; i < records.Count; i++){
                    int RecordNumber = i;
                    Entry_Records records_to_add = new Entry_Records(request.recordsID,i+1, records[i], request.Timestamp, request.expireAt);
                    dbRecords.Add(records_to_add);
                    Console.WriteLine("Added");
                }
            }
            try{
                Table Records = Table.LoadTable(client, RecordsTable);
                for (int j = 0; j<dbRecords.Count; j++){
                    string jsonString = System.Text.Json.JsonSerializer.Serialize(dbRecords[j]);
                    Console.WriteLine(jsonString);
                    Document doc = Document.FromJson(jsonString);
                    var task = Records.PutItemAsync(doc);
                }
            }
            catch(Exception e){
                Console.WriteLine(e);
            }

        }
        public void update_entry(LdapResponse response, LdapRequest request){
            int? updated_totalRecords = response.TotalRecords;
            string updated_message = response.Message;
            string updated_status = response.Status.ToString();
            Console.WriteLine(updated_status);
            write_to_records_Table(response.Records, request);
            if(updated_status == "Success"){
                var find_item = new UpdateItemRequest{
                    TableName = RequestsTable,
                    Key = new Dictionary<string,AttributeValue>() { { "JobID", new AttributeValue { S = request.jobID } } },
                    ExpressionAttributeNames = new Dictionary<string,string>(){
                        {"#C", "Completed"},
                        {"#T", "TotalRecords"}
                    },
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>(){
                        {":status",new AttributeValue {S = "Success"}},
                        {":total", new AttributeValue {N = $"{updated_totalRecords}"}}
                    },
                    UpdateExpression = "SET  #C = :status, #T = :total",
                    ReturnValues="UPDATED_NEW"
                };
                var item = client.UpdateItemAsync(find_item);
                Console.WriteLine(item.Result);
            }
            else{
                var find_item = new UpdateItemRequest{
                    TableName = RequestsTable,
                    Key = new Dictionary<string,AttributeValue>() { { "JobID", new AttributeValue { S = request.jobID } } },
                    ExpressionAttributeNames = new Dictionary<string,string>(){
                        {"#C", "Completed"},
                        {"#T", "TotalRecords"},
                        {"#M", "Message"}
                    },
                    ExpressionAttributeValues = new Dictionary<string, AttributeValue>(){
                        {":status",new AttributeValue {S = updated_status}},
                        {":total", new AttributeValue {N = $"{updated_totalRecords}"}},
                        {":message", new AttributeValue {S = updated_message}}
                    },
                    UpdateExpression = "SET  #C = :status, #T = :total, #M = :message",
                    ReturnValues="UPDATED_NEW"
                };
                var item = client.UpdateItemAsync(find_item);
                Console.WriteLine(item.Result);
            }

        }

        public LdapResponse Batch_Retrieval(LdapRequest ldapRequest){
            Console.WriteLine(ldapRequest.jobID);
            LdapResponse response1 = new LdapResponse();
            
            string jobID = ldapRequest.jobID;
            var check = new GetItemRequest{
                TableName = RequestsTable,
                Key = new Dictionary<string,AttributeValue>() {{ "JobID", new AttributeValue { S = jobID }}}
            };
            var response = client.GetItemAsync(check).Result.Item;
            if(response["Completed"].S != "Success"){
                throw new Exception("Batch Failed");
            }
            else{
                var check2 = new QueryRequest{};
                if(ldapRequest.NextToken != null & ldapRequest.MaxResults.HasValue){
                    int to_token_int = Int32.Parse(ldapRequest.NextToken)+ldapRequest.MaxResults.Value;
                    check2 = new QueryRequest{
                        TableName = RecordsTable,
                        KeyConditionExpression =  "RecordsID = :id AND RecordNumber BETWEEN :next AND :max",
                        ExpressionAttributeValues = new Dictionary<string, AttributeValue> {
                            {":id", new AttributeValue { S = response["recordsID"].S }},
                            {":next", new AttributeValue {N =(Int32.Parse(ldapRequest.NextToken)+1).ToString()}},
                            {":max", new AttributeValue {N = (Int32.Parse(ldapRequest.NextToken)+ldapRequest.MaxResults.Value).ToString()}}
                        }
                    };
                }
                else if(ldapRequest.NextToken == null & ldapRequest.MaxResults.HasValue){
                    check2 = new QueryRequest{
                        TableName = RecordsTable,
                        KeyConditionExpression =  "RecordsID = :id AND RecordNumber <= :max",
                        ExpressionAttributeValues = new Dictionary<string, AttributeValue> {
                            {":id", new AttributeValue { S = response["recordsID"].S }},
                            {":max", new AttributeValue {N = ldapRequest.NextToken+ldapRequest.MaxResults.Value}}
                        }
                    };
                }
                else if(ldapRequest.NextToken != null & ldapRequest.MaxResults == null){
                    check2 = new QueryRequest{
                        TableName = RecordsTable,
                        KeyConditionExpression =  "RecordsID = :id AND RecordNumber > :max",
                        ExpressionAttributeValues = new Dictionary<string, AttributeValue> {
                            {":id", new AttributeValue { S = response["recordsID"].S }},
                            {":max", new AttributeValue {N = ldapRequest.NextToken}}
                        }
                    };
                }
                else{
                    check2 = new QueryRequest{
                        TableName = RecordsTable,
                        KeyConditionExpression =  "RecordsID = :id",
                        ExpressionAttributeValues = new Dictionary<string, AttributeValue> {
                            {":id", new AttributeValue { S = response["recordsID"].S }}
                        }
                    };
                }
                var records_response = client.QueryAsync(check2).Result.Items;
                List<LdapObject> records_list = new List<LdapObject>();
                using (IDynamoDBContext dbcontext = new DynamoDBContext(client)){
                    foreach (var item in records_response){
                        Document doc = Document.FromAttributeMap(item);
                        Document test = doc["Record"].AsDocument();

                        LdapObject to_add = new LdapObject();
                        to_add.DistinguishedName = test.Values.ElementAt(1);
                        Document test2 = test["Attributes"].AsDocument();
                        foreach (var entry in test2){
                            Console.WriteLine(entry.Value.GetType());
                            if(entry.Value.GetType() == typeof(DynamoDBList)){
                                to_add.Attributes.Add(entry.Key, entry.Value.AsListOfString());
                            }
                            else if(entry.Value.GetType() == typeof(Primitive)){
                                int number;
                                var isNumeric = int.TryParse(entry.Value, out number);
                                if(isNumeric){
                                    to_add.Attributes.Add(entry.Key, entry.Value.AsInt());
                                }
                                else{
                                    to_add.Attributes.Add(entry.Key, entry.Value.ToString());
                                }
                            }
                            else{
                                to_add.Attributes.Add(entry.Key, entry.Value.ToString());
                            }
                        }
                        records_list.Add(to_add);
                        // Console.WriteLine(records_list);
                    }
                    if(records_list.Count < Int32.Parse(response["TotalRecords"].N)){
                        if(ldapRequest.NextToken != null){
                            if(Int32.Parse(ldapRequest.NextToken) + records_list.Count < Int32.Parse(response["TotalRecords"].N)){
                                response1.NextToken = (Int32.Parse(ldapRequest.NextToken) + records_list.Count).ToString();
                            }
                        }
                        else{
                            response1.NextToken = records_list.Count.ToString();
                        }
                    }
                }
                response1.Records = records_list;
            }
            // Console.WriteLine(response["recordsID"].S);
            return response1;
        }
    }
}