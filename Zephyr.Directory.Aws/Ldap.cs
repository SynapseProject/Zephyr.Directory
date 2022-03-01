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
        public static string Encrypt(LdapCrypto request, ILambdaContext ctx)
        {
            LdapCrypto crypto = LdapUtils.ApplyDefaulsAndValidate(request);
            string encrypted = Rijndael.Encrypt(crypto.TextValue, crypto.PassPhrase, crypto.SaltValue, crypto.InitVector);
            return encrypted;
        }

        public static LdapResponse Search(LdapRequest request, ILambdaContext ctx)
        {
            LdapUtils.ApplyDefaulsAndValidate(request);

            LdapServer ldap = new LdapServer(request.Config);
            ldap.Connect();
            ldap.Bind(request.Config);
            LdapResponse response = ldap.Search(request.Search);
            ldap.Disconnect();

            return response;
        }
    }
}
