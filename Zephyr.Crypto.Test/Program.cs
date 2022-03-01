using System;

using Zephyr.Crypto;

namespace Zephyr.Crypto.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            string _plaintext = "Plain text";
            string _passPhrase = "PassPhrase";
            string _saltValue = "SaltValue";
            string _iv = "1234567890123456";    // length must be block size (128) / 8 = 16

            string _encryptedText = Rijndael.Encrypt(_plaintext, _passPhrase, _saltValue, _iv);
            Console.WriteLine(_encryptedText);
            string _decryptedText = Rijndael.Decrypt(_encryptedText, _passPhrase, _saltValue, _iv);
            Console.WriteLine(_decryptedText);
        }
    }
}
