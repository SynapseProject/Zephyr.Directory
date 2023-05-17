using System;
using System.Security.Cryptography;
using System.IO;

using Zephyr.Crypto;

namespace Zephyr.Crypto.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            // Test Rijndael Encrytpion
            string _plaintext = "Plain text";
            string _passPhrase = "PassPhrase";
            string _saltValue = "SaltValue";
            string _iv = "1234567890123456";    // length must be block size (128) / 8 = 16

            string _encryptedText = Rijndael.Encrypt(_plaintext, _passPhrase, _saltValue, _iv);
            Console.WriteLine(_encryptedText);
            string _decryptedText = Rijndael.Decrypt(_encryptedText, _passPhrase, _saltValue, _iv);
            Console.WriteLine(_decryptedText);


            // Test RSA Encryption
            //string filePath = @"/tmp";
            //string pubPrivFilename = $"{filePath}/pubPriv.xml";
            //string pubOnlyFilename = $"{filePath}/pubOnly.xml";

            //string text = "Hello World";

            //Rsa.GenerateRsaKeys(pubPrivFilename, pubOnlyFilename, 2048);

            //RSA rsa = Rsa.LoadRsaKeys(pubOnlyFilename);
            //string encrypted = Rsa.Encrypt(rsa, text);
            //Console.WriteLine(encrypted);

            //rsa = Rsa.LoadRsaKeys(pubPrivFilename);
            //string decrypted = Rsa.Decrypt(rsa, encrypted);
            //Console.WriteLine(decrypted);

            //File.Delete(pubPrivFilename);
            //File.Delete(pubOnlyFilename);
        }
    }
}
