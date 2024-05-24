using System;
using Zephyr.Crypto;

namespace Zephyr.Directory.Ldap
{
	public class LdapEngine
	{
		public static LdapResponse Process(LdapRequest request)
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
                    if (request.Config.TokenType == "Server" || request.Config.TokenType == "Client")
                    {
                        response = ldap.Search(request, request.SearchBase, searchFilter, request.Attributes, request.SearchScope, request.MaxResults, request.NextToken, request.Union);
                    }
                    else
                    {
                        throw new FormatException("Warning: TokenType must be set to Server or Client");
                    }
                    ldap.Disconnect();
                }
                catch (Exception e)
                {
                    response = LdapServer.ReturnError(e, request.Config);
                }
            }

            return response;
        }
    }
}

