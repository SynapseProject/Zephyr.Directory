﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace Zephyr.Crypto
{
    public class Rijndael
    {
        const int _keySize = 256;
        const string _hashAlgorithm = "SHA1";
        const int _pwdIterations = 2;

        public static string Encrypt(string plainText, string passPhrase, string saltValue, string initVector)
        {
            // Siew Hooi: commented try catch 
            //try
            {
                // Convert strings into byte arrays.
                // Let us assume that strings only contain ASCII codes.
                // If strings include Unicode characters, use Unicode, UTF7, or UTF8
                // encoding.
                byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
                byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

                // Convert our plaintext into a byte array.
                // Let us assume that plaintext contains UTF8-encoded characters.
                byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

                // First, we must create a password, from which the key will be derived.
                // This password will be generated from the specified passphrase and
                // salt value. The password will be created using the specified hash
                // algorithm. Password creation can be done in several iterations.
                // Siew Hooi: replaced PasswordDeriveBytes with Rfc2898DeriveBytes as the former is obsolete
                //PasswordDeriveBytes password = new PasswordDeriveBytes(
                //    passPhrase,
                //    saltValueBytes,
                //    _hashAlgorithm,
                //    _pwdIterations);
                Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(
                    passPhrase,
                    saltValueBytes,
                    _pwdIterations);

                // Use the password to generate pseudo-random bytes for the encryption
                // key. Specify the size of the key in bytes (instead of bits).
                byte[] keyBytes = password.GetBytes(_keySize / 8);

                // Create uninitialized Rijndael encryption object.
                Aes symmetricKey = Aes.Create("AesManaged");

                // It is reasonable to set encryption mode to Cipher Block Chaining
                // (CBC). Use default options for other symmetric key parameters.
                symmetricKey.Mode = CipherMode.CBC;

                // Generate encryptor from the existing key bytes and initialization
                // vector. Key size will be defined based on the number of the key
                // bytes.
                ICryptoTransform encryptor = symmetricKey.CreateEncryptor(
                    keyBytes,
                    initVectorBytes);

                // Define memory stream which will be used to hold encrypted data.
                MemoryStream memoryStream = new MemoryStream();

                // Define cryptographic stream (always use Write mode for encryption).
                CryptoStream cryptoStream = new CryptoStream(memoryStream,
                    encryptor,
                    CryptoStreamMode.Write);
                // Start encrypting.
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

                // Finish encrypting.
                cryptoStream.FlushFinalBlock();

                // Convert our encrypted data from a memory stream into a byte array.
                byte[] cipherTextBytes = memoryStream.ToArray();

                // Close both streams.
                memoryStream.Close();
                cryptoStream.Close();

                // Convert encrypted data into a base64-encoded string.
                string cipherText = Convert.ToBase64String(cipherTextBytes);

                // Return encrypted string.
                return cipherText;
            }
            //catch (Exception err)
            //{
            //    return "UNABLE TO ENCRYPT - Error: " + err.Message;
            //}
        }

        public static string Decrypt(string cipherText, string passPhrase, string saltValue, string initVector)
        {
            // Siew Hooi: commented try catch
            //try
            {
                // Convert strings defining encryption key characteristics into byte
                // arrays. Let us assume that strings only contain ASCII codes.
                // If strings include Unicode characters, use Unicode, UTF7, or UTF8
                // encoding.
                byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
                byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

                // Convert our ciphertext into a byte array.
                byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

                // First, we must create a password, from which the key will be
                // derived. This password will be generated from the specified
                // passphrase and salt value. The password will be created using
                // the specified hash algorithm. Password creation can be done in
                // several iterations.
                // Siew Hooi: replace PasswordDeriveBytes with Rfc2898DeriveBytes as the former is obsolete
                //PasswordDeriveBytes password = new PasswordDeriveBytes(
                //    passPhrase,
                //    saltValueBytes,
                //    _hashAlgorithm,
                //    _pwdIterations);
                Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(
                    passPhrase,
                    saltValueBytes,
                    _pwdIterations);

                // Use the password to generate pseudo-random bytes for the encryption
                // key. Specify the size of the key in bytes (instead of bits).
                byte[] keyBytes = password.GetBytes(_keySize / 8);

                // Create uninitialized Rijndael encryption object.
                Aes symmetricKey = Aes.Create("AesManaged");

                // It is reasonable to set encryption mode to Cipher Block Chaining
                // (CBC). Use default options for other symmetric key parameters.
                symmetricKey.Mode = CipherMode.CBC;

                // Generate decryptor from the existing key bytes and initialization
                // vector. Key size will be defined based on the number of the key
                // bytes.
                ICryptoTransform decryptor = symmetricKey.CreateDecryptor(
                    keyBytes,
                    initVectorBytes);

                string plainText = null;
                // Define memory stream which will be used to hold encrypted data.
                using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
                {
                    // Define cryptographic stream (always use Read mode for encryption).
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        // Read the decrypted bytes from the decrypting stream and place them in a string
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }

                // Return decrypted string.
                return plainText;
            }
            //catch (Exception err)
            //{
            //    return "UNABLE TO DECRYPT - Error: " + err.Message;
            //}
        }
    }
}