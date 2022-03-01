using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Zephyr.Crypto
{
    public class Rsa
    {
        #region RsaKeys
        public static void GenerateRsaKeys(string keyContainerName = null, string pubPrivFilePath = null, string pubOnlyFilePath = null, int keySize = 0)
        {
            if (string.IsNullOrWhiteSpace(keyContainerName) && string.IsNullOrWhiteSpace(pubPrivFilePath) && string.IsNullOrWhiteSpace(pubOnlyFilePath))
                throw new ArgumentException("Invalid argument");

            CspParameters cspParams = new CspParameters
            {
                KeyContainerName = keyContainerName
            };
            GenerateRsaKeys(cspParams, pubPrivFilePath, pubOnlyFilePath, keySize);
        }
        public static void GenerateRsaKeys(CspParameters cspParams, string pubPrivFilePath, string pubOnlyFilePath, int keySize = 0)
        {
            RSACryptoServiceProvider rsaKey = keySize > 0 ?
                new RSACryptoServiceProvider(keySize, cspParams) :
                new RSACryptoServiceProvider(cspParams);


            if (!string.IsNullOrEmpty(pubPrivFilePath))
            {
                using (StreamWriter sw = new StreamWriter(pubPrivFilePath))
                {
                    sw.Write(rsaKey.ToXmlString(true));
                }
            }

            if (!string.IsNullOrEmpty(pubOnlyFilePath))
            {
                using (StreamWriter sw = new StreamWriter(pubOnlyFilePath))
                {
                    sw.Write(rsaKey.ToXmlString(false));
                }
            }
        }

        public static RSACryptoServiceProvider LoadRsaKeys(string keyContainerName = null, string filePath = null, CspProviderFlags flags = CspProviderFlags.NoFlags)
        {
            CspParameters cspParams = new CspParameters
            {
                KeyContainerName = keyContainerName,
                Flags = flags
            };

            return LoadRsaKeys(cspParams, !string.IsNullOrWhiteSpace(keyContainerName) ? null : filePath);
        }

        public static RSACryptoServiceProvider LoadRsaKeys(CspParameters cspParams, string filePath)
        {
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(cspParams);

            if (string.IsNullOrWhiteSpace(filePath))
                return rsaKey;
            else
            {
                try
                {
                    Uri uri = new Uri(filePath);
                    string uriContent = WebRequestClient.GetString(uri.ToString());
                    try { rsaKey.FromXmlString(uriContent); }
                    catch { rsaKey.FromXmlStringZephyr(uriContent); }
                }
                catch
                {
                    try
                    {
                        using (StreamReader sr = new StreamReader(filePath))
                            try { rsaKey.FromXmlString(sr.ReadToEnd()); }
                            catch { rsaKey.FromXmlStringZephyr(sr.ReadToEnd()); }
                    }
                    catch (Exception innerEx)
                    {
                        throw new FileNotFoundException($"Could not load RSA keys from [{filePath}].", innerEx);
                    }
                }

                return rsaKey;
            }
        }
        #endregion


        #region Encrypt
        public static string EncryptFromFileKeys(string filePath, string value)
        {
            return Encrypt(filePath: filePath, value: value);
        }

        public static string EncryptFromFileKeys(string filePath, string value, CspProviderFlags flags)
        {
            return Encrypt(filePath: filePath, flags: flags, value: value);
        }

        public static string EncryptFromContainerKeys(string keyContainerName, string value)
        {
            return Encrypt(keyContainerName: keyContainerName, value: value);
        }

        public static string EncryptFromContainerKeys(string keyContainerName, string value, CspProviderFlags flags)
        {
            return Encrypt(keyContainerName: keyContainerName, flags: flags, value: value);
        }

        public static string Encrypt(string keyContainerName = null, string filePath = null, CspProviderFlags flags = CspProviderFlags.NoFlags, string value = null)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Invalid argument");

            RSACryptoServiceProvider rsa = null;
            if (!string.IsNullOrWhiteSpace(keyContainerName))   // container name takes precedence over file
                rsa = LoadRsaKeys(keyContainerName: keyContainerName, flags: flags);
            else if (!string.IsNullOrWhiteSpace(filePath))
                rsa = LoadRsaKeys(filePath: filePath, flags: flags);
            else
                throw new ArgumentException("Missing key container name or path to key file.");

            return Encrypt(rsa, value);
        }

        public static string Encrypt(RSACryptoServiceProvider rsa, string value)
        {
            byte[] valueBytes = Encoding.ASCII.GetBytes(value);
            byte[] encrypted = rsa.Encrypt(valueBytes, false);
            return Convert.ToBase64String(encrypted);
        }
        #endregion


        #region Decrypt
        public static string DecryptFromFileKeys(string filePath, string value)
        {
            return Decrypt(filePath: filePath, value: value);
        }

        public static string DecryptFromFileKeys(string filePath, string value, CspProviderFlags flags)
        {
            return Decrypt(filePath: filePath, flags: flags, value: value);
        }

        public static string DecryptFromContainerKeys(string keyContainerName, string value)
        {
            return Decrypt(keyContainerName: keyContainerName, value: value);
        }

        public static string DecryptFromContainerKeys(string keyContainerName, string value, CspProviderFlags flags)
        {
            return Decrypt(keyContainerName: keyContainerName, flags: flags, value: value);
        }

        public static string Decrypt(string keyContainerName = null, string filePath = null, CspProviderFlags flags = CspProviderFlags.NoFlags, string value = null)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Invalid argument");

            RSACryptoServiceProvider rsa = null;
            // container name takes precedence over file
            if (!string.IsNullOrWhiteSpace(keyContainerName))
                // set the UseExistingKey so that rsacryptoserviceprovider doesnt go and generate new keys
                rsa = LoadRsaKeys(keyContainerName: keyContainerName, flags: flags | CspProviderFlags.UseExistingKey);
            else if (!string.IsNullOrWhiteSpace(filePath))
                rsa = LoadRsaKeys(filePath: filePath, flags: flags);
            else
                throw new ArgumentException("Missing key container name or path to key file.");

            return Decrypt(rsa, value);
        }

        public static string Decrypt(RSACryptoServiceProvider rsa, string value)
        {
            byte[] valueBytes = Convert.FromBase64String(value);
            byte[] decrypted = rsa.Decrypt(valueBytes, false);
            return Encoding.ASCII.GetString(decrypted);
        }
        #endregion


        public static bool KeyContainerExists(string keyContainerName)
        {
            CspParameters cspParams = new CspParameters
            {
                Flags = CspProviderFlags.UseExistingKey,
                KeyContainerName = keyContainerName
            };

            try
            {
                new RSACryptoServiceProvider(cspParams);
                return true;
            }
            catch
            {
                return false;
            }

        }
    }

    //https://github.com/dotnet/core/issues/874
    public static class RsaExtensions
    {
        public static void FromXmlStringZephyr(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlStringZephyr(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }
    }
}