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
        public static void GenerateRsaKeys(string pubPrivFilePath, string pubOnlyFilePath, int keySize = 0)
        {
            RSA rsaKey = keySize > 0 ?
                RSA.Create(keySize) :
                RSA.Create();


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

        public static RSA LoadRsaKeys(string filePath)
        {
            RSA rsaKey = RSA.Create();

            if (string.IsNullOrWhiteSpace(filePath))
                return rsaKey;
            else
            {
                try
                {
                    string uriContent = File.ReadAllText(filePath);
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
        public static string Encrypt(string filePath, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Invalid argument");

            RSA rsa = null;
            if (!string.IsNullOrWhiteSpace(filePath))
                rsa = LoadRsaKeys(filePath);
            else
                throw new ArgumentException("Missing key container name or path to key file.");

            return Encrypt(rsa, value);
        }

        public static string Encrypt(RSA rsa, string value)
        {
            byte[] valueBytes = Encoding.ASCII.GetBytes(value);
            byte[] encrypted = rsa.Encrypt(valueBytes, RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(encrypted);
        }
        #endregion


        #region Decrypt
        public static string Decrypt(string filePath, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentException("Invalid argument");

            RSA rsa = null;
            if (!string.IsNullOrWhiteSpace(filePath))
                rsa = LoadRsaKeys(filePath);
            else
                throw new ArgumentException("Missing key container name or path to key file.");

            return Decrypt(rsa, value);
        }

        public static string Decrypt(RSA rsa, string value)
        {
            byte[] valueBytes = Convert.FromBase64String(value);
            byte[] decrypted = rsa.Decrypt(valueBytes, RSAEncryptionPadding.Pkcs1);
            return Encoding.ASCII.GetString(decrypted);
        }
        #endregion
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