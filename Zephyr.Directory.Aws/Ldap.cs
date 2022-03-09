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
            if (request.Type != RequestType.Encrypt)
                Console.WriteLine("REQUEST - " + JsonTools.Serialize(request, false));

            if (request.Type == RequestType.Encrypt)
            {
                LdapCrypto crypto = LdapUtils.ApplyDefaulsAndValidate(request.Crypto);
                response.Value = Rijndael.Encrypt(request.Value, crypto.PassPhrase, crypto.SaltValue, crypto.InitVector);
            }
            else
            {
                LdapUtils.ApplyDefaulsAndValidate(request);

                LdapServer ldap = new LdapServer(request.Config);
                ldap.Connect();
                ldap.Bind(request.Config);
                response = ldap.Search(request.Search);
                ldap.Disconnect();
            }

            response.Type = request.Type;
            if (request.Type != RequestType.Encrypt)
                Console.WriteLine("RESPONSE - " + JsonTools.Serialize(response, false));

            return response;
        }
    }
}
