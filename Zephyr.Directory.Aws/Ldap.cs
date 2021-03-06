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
            LdapResponse response = new LdapResponse();
            bool isEncryptionRequest = request.Crypto?.Text != null;
            bool isPing = request.Ping.HasValue;

            if (!isEncryptionRequest && !isPing)
                Console.WriteLine("REQUEST - " + JsonTools.Serialize(request, false));

            if (isEncryptionRequest)
            {
                LdapCrypto crypto = LdapUtils.ApplyDefaulsAndValidate(request.Crypto);
                response.Message = Rijndael.Encrypt(crypto.Text, crypto.PassPhrase, crypto.SaltValue, crypto.InitVector);
            }
            else if (isPing)
            {
                response.Message = "Hello From MyriAD.";
                if (request.Ping == PingType.Echo)
                    Console.WriteLine("Ping");
            }
            else
            {
                LdapUtils.ApplyDefaulsAndValidate(request);
                string searchFilter = LdapUtils.GetSearchString(request);

                LdapServer ldap = new LdapServer(request.Config);
                ldap.Bind(request.Config);
                response = ldap.Search(request.SearchBase, searchFilter, request.Attributes);
                ldap.Disconnect();
            }

            if (!isEncryptionRequest && !isPing)
                Console.WriteLine("RESPONSE - " + JsonTools.Serialize(response, false));

            return response;
        }
    }
}
