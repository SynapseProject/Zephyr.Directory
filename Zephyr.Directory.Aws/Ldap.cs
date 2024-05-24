using System;

using Amazon.Lambda.Core;

using Zephyr.Crypto;
using Zephyr.Directory.Ldap;

// Allows Lambda Function's JSON Input to be converted into a .NET class
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace Zephyr.Directory.Aws
{
    public class Ldap
    {
        public static LdapResponse ProcessRequest(LdapRequest request, ILambdaContext ctx)
        {
            bool isEncryptionRequest = request.Crypto?.Text != null;
            bool isPing = request.Ping.HasValue;

            if (!isEncryptionRequest && !isPing)
                Console.WriteLine("REQUEST - " + JsonTools.Serialize(request, false));

            LdapResponse response = request.Process();

            if (!isEncryptionRequest && !isPing)
                Console.WriteLine("RESPONSE - " + JsonTools.Serialize(response, false));

            return response;
        }
    }
}
