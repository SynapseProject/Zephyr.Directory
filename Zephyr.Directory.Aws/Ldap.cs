using System;

using Amazon.Lambda.Core;

using Zephyr.Directory.Ldap;

// Allows Lambda Function's JSON Input to be converted into a .NET class
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace Zephyr.Directory.Aws
{
    public class Ldap
    {
        public static string Test(LdapRequest request, ILambdaContext ctx)
        {
            LdapUtils.ApplyDefaulsAndValidate(request);

            LdapServer ldap = new LdapServer(request.Config);
            ldap.Connect();
            ldap.Bind(request.Config);
            ldap.Search(request.Search);
            ldap.Disconnect();

            return "Success";
        }
    }
}
