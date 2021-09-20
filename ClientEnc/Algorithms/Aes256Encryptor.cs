using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Text;

namespace ClientEnc.Algorithms
{
    public class Aes256Encryptor : ISymmetricEncryptor
    {
        private static Random r = new Random();
        public string Decrypt(string key, string encoded)
        {
            if (string.IsNullOrEmpty(key)) key = "";
            string[] parts = encoded.Split(":");
            if (parts.Length != 2) throw new Exception("Wrong encoded message format");
            var (IV, encodedBytes) = (parts[0].FromShortStringB58(), parts[1].FromShortStringB58());

            byte[] sha256key = Sha256Bytes(key);

            AesEngine engine = new();
            CbcBlockCipher blockCipher = new(engine);
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());
            KeyParameter keyParam = new KeyParameter(sha256key, 0, sha256key.Length);
            ParametersWithIV keyParamWithIv = new ParametersWithIV(keyParam, IV);


            cipher.Init(false, keyParamWithIv);
            byte[] outputBytes = new byte[cipher.GetOutputSize(encodedBytes.Length)]; //cip
            int length = cipher.ProcessBytes(encodedBytes, outputBytes, 0);
            cipher.DoFinal(outputBytes, length); //Do the final block

            string res = Encoding.UTF8.GetString(outputBytes);
            return res.Trim('\0');
        }

        public string Encrypt(string key, string plaintext)
        {
            if (string.IsNullOrEmpty(key)) key = "";
            var inputBytes = Encoding.UTF8.GetBytes(plaintext);
            // key - sha256 of key

            byte[] sha256key = Sha256Bytes(key);

            byte[] IV = new byte[16];
            r.NextBytes(IV);

            AesEngine engine = new();
            CbcBlockCipher blockCipher = new(engine);
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());
            KeyParameter keyParam = new KeyParameter(sha256key, 0, sha256key.Length);
            ParametersWithIV keyParamWithIv = new ParametersWithIV(keyParam, IV);


            cipher.Init(true, keyParamWithIv);
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)]; //cip
            int length = cipher.ProcessBytes(inputBytes, outputBytes, 0);
            cipher.DoFinal(outputBytes, length); //Do the final block

            string encryptedInput = outputBytes.ToShortStringB58();

            return $"{IV.ToShortStringB58()}:{encryptedInput}";
        }

        private static byte[] Sha256Bytes(string key)
        {
            var keyBytes = Encoding.UTF8.GetBytes(key);
            Sha256Digest myHash = new();
            myHash.BlockUpdate(keyBytes, 0, keyBytes.Length);
            byte[] sha256key = new byte[myHash.GetDigestSize()];
            myHash.DoFinal(sha256key, 0);
            return sha256key;
        }
    }
    public static class BaseXXUtils
    {
        public static string ToShortStringB58(this byte[] input)
        {
            var base58Guid = SimpleBase.Base58.Bitcoin.Encode(input);
            return base58Guid;
        }

        public static byte[] FromShortStringB58(this string str)
        {
            var byteArray = SimpleBase.Base58.Bitcoin.Decode(str).ToArray();
            return byteArray;
        }
    }
}
