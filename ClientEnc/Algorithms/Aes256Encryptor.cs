using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClientEnc.Algorithms
{
    public class Aes256Encryptor : ISymmetricEncryptor
    {
        private static SecureRandom r = new SecureRandom();
        public string Decrypt(string key, string encoded)
        {
            if (string.IsNullOrEmpty(key)) key = "";
            string[] parts = encoded.Split(":");
            if (parts.Length != 2) throw new Exception("Wrong encoded message format");
            var (IV, encodedBytes) = (Convert.FromBase64String(parts[0]), Convert.FromBase64String(parts[1]));

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

            string encryptedInput = Convert.ToBase64String(outputBytes);

            return $"{Convert.ToBase64String(IV)}:{encryptedInput}";
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
}
