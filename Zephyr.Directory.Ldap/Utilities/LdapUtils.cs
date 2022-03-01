using System;
using System.Text;
using System.Collections.Generic;

using Zephyr.Crypto;

namespace Zephyr.Directory.Ldap
{
    public class LdapUtils
    {
        public static string GetEnvironmentVariable(string name, string defaultValue = null)
        {
            return GetEnvironmentVariable<string>(name, defaultValue);
        }

        public static T GetEnvironmentVariable<T>(string name)
        {
            return GetEnvironmentVariable<T>(name, (T)Convert.ChangeType(null, typeof(T)));
        }

        public static T GetEnvironmentVariable<T>(string name, T defaultValue) 
        {
            string value = Environment.GetEnvironmentVariable(name);

            if (value == null)
                value = defaultValue?.ToString();

            return (T)Convert.ChangeType(value, typeof(T));
        }

        public static LdapRequest ApplyDefaulsAndValidate(LdapRequest request)
        {
            // Set Config Defaults
            if (request.Config == null)
                request.Config = new LdapConfig();

            if (request.Config.Server == null)
                request.Config.Server = LdapUtils.GetEnvironmentVariable<string>("server", Environment.MachineName);

            if (request.Config.Port == null)
                request.Config.Port = LdapUtils.GetEnvironmentVariable<int>("port", 389);

            if (request.Config.UseSSL == null)
                request.Config.UseSSL = LdapUtils.GetEnvironmentVariable<bool>("useSSL", false);

            if (request.Config.Username == null)
                request.Config.Username = LdapUtils.GetEnvironmentVariable<string>("username");

            if (request.Config.Password == null)
                request.Config.Password = LdapUtils.GetEnvironmentVariable<string>("password");

            if (request.Config.AttributeTypes == null)
            {
                string attrConfigStr = LdapUtils.GetEnvironmentVariable<string>("returnTypes");
                if (!String.IsNullOrWhiteSpace(attrConfigStr))
                {
                    LdapConfig attrConfig = JsonTools.Deserialize<LdapConfig>(attrConfigStr);
                    request.Config.AttributeTypes = attrConfig.AttributeTypes;
                }
            }

            // Set Search Defaults
            if (request.Search == null)
                request.Search = new LdapSearch();

            if (request.Search.Base == null)
                request.Search.Base = LdapUtils.GetEnvironmentVariable<string>("searchBase");

            // Set Crypto Defaults
            if (request.Crypto == null)
                request.Crypto = new Crypto();

            if (request.Crypto.InitVector == null)
                request.Crypto.InitVector = LdapUtils.GetEnvironmentVariable<string>("iv", "1234567890ABCDEF");

            if (request.Crypto.SaltValue == null)
                request.Crypto.SaltValue = LdapUtils.GetEnvironmentVariable<string>("salt", "DefaultSaltValue");

            if (request.Crypto.PassPhrase == null)
                request.Crypto.PassPhrase = LdapUtils.GetEnvironmentVariable<string>("passphrase", "DefaultPassPhrase");

            // Validate Request
            if (request.Search.Filter == null)
                throw new Exception("Search Filter Not Provided.");

            // Attempt To Decrypt Password
            try { request.Config.Password = Rijndael.Decrypt(request.Config.Password, request.Crypto.PassPhrase, request.Crypto.SaltValue, request.Crypto.InitVector); }
            catch { }

            return request;
        }

        // Taken from Stack Overflow Solution
        // https://stackoverflow.com/questions/47209459/adding-all-users-sids-from-active-directory-in-c-sharp
        //
        public static string ConvertByteToStringSid(Byte[] sidBytes)
        {
            StringBuilder strSid = new StringBuilder();
            strSid.Append("S-");
            try
            {
                // Add SID revision.
                strSid.Append(sidBytes[0].ToString());
                // Next six bytes are SID authority value.
                if (sidBytes[6] != 0 || sidBytes[5] != 0)
                {
                    string strAuth = String.Format
                        ("0x{0:2x}{1:2x}{2:2x}{3:2x}{4:2x}{5:2x}",
                        (Int16)sidBytes[1],
                        (Int16)sidBytes[2],
                        (Int16)sidBytes[3],
                        (Int16)sidBytes[4],
                        (Int16)sidBytes[5],
                        (Int16)sidBytes[6]);
                    strSid.Append("-");
                    strSid.Append(strAuth);
                }
                else
                {
                    Int64 iVal = (Int32)(sidBytes[1]) +
                        (Int32)(sidBytes[2] << 8) +
                        (Int32)(sidBytes[3] << 16) +
                        (Int32)(sidBytes[4] << 24);
                    strSid.Append("-");
                    strSid.Append(iVal.ToString());

                    // Get sub authority count...
                    int iSubCount = Convert.ToInt32(sidBytes[7]);
                    int idxAuth = 0;
                    for (int i = 0; i < iSubCount; i++)
                    {
                        idxAuth = 8 + i * 4;
                        UInt32 iSubAuth = BitConverter.ToUInt32(sidBytes, idxAuth);
                        strSid.Append("-");
                        strSid.Append(iSubAuth.ToString());
                    }
                }
            }
            catch (Exception ex)
            {

            }
            return strSid.ToString();
        }
    }
}
