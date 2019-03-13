using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            //and of course we could use a key container for storing an asymmetric key
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string publicKeyXML = rsa.ToXmlString(false); //public key
            string privateKeyXML = rsa.ToXmlString(true); //+ private key

            //data input
            Console.Write("Enter the string you want to encrypt and then decrypt: ");
            string original = Console.ReadLine();


            byte[] encryptedData;
            encryptingString(original, publicKeyXML, out encryptedData);

            string decryptedString;
            decryptingData(encryptedData, privateKeyXML, out decryptedString);


            //information output
            InformationOutput(original, encryptedData, decryptedString);


            Console.ReadKey();
        }

        //string conversion to encrypted byte array
        public static void encryptingString(string stringToEncrypt, string publicKeyXML, out byte[] encryptedData)
        {
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            //convert string to byte array
            byte[] dataToEncrypt = ByteConverter.GetBytes(stringToEncrypt);

            //Encrypt
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(publicKeyXML);
                encryptedData = RSA.Encrypt(dataToEncrypt, false);
            }
        }

        //convert byte array to decrypted string
        public static void decryptingData(byte[] dataToDecrypt, string privateKeyXML, out string decryptedString)
        {
            byte[] decryptedData;

            //Decrypt
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.FromXmlString(privateKeyXML);
                decryptedData = RSA.Decrypt(dataToDecrypt, false);
            }

            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            //convert byte array to string
            decryptedString = ByteConverter.GetString(decryptedData);
        }

        //method to encrypt data by a specific method (SymmetricAlgorithm aesAlg)
        public static byte[] Encrypt(SymmetricAlgorithm aesAlg, string plainText)
        {
            //encryption options
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            //data storage area
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                //stream to create encrypted data
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    //stream to write encrypted data memory
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //write data to memory
                        swEncrypt.Write(plainText);
                    }
                    //returning an array of bytes of encrypted data
                    return msEncrypt.ToArray();
                }
            }
        }

        //method to decrypt data by a specific method (SymmetricAlgorithm aesAlg)
        public static string Decrypt(SymmetricAlgorithm aesAlg, byte[] plainByteArray)
        {
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(plainByteArray))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        //return decrypted string
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        public static void InformationOutput(string original, byte[] encryptedData, string result)
        {
            Console.WriteLine($"Original: {original}\n");

            Console.Write("Encrypted: ");
            foreach (byte item in encryptedData)
            {
                Console.Write(item + " ");
            }
            Console.WriteLine("\n");

            Console.WriteLine($"Round trip: {result}");
        }
    }
}
