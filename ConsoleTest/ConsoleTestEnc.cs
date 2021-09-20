using ClientEnc.Algorithms;
using System;

namespace ConsoleTest
{
    class ConsoleTestEnc
    {
        static void Main(string[] args)
        {
            var key = "awsome KeY";
            var text = "Strange test to encrypt, Strange test to encrypt, Strange test to encrypt, Strange test to encrypt, Strange test to encrypt, Strange test to encrypt, Strange test to encrypt, Strange test to encrypt, ";
            var enc = new Aes256Encryptor();
            var encr = enc.Encrypt(key, text);
            var decr = enc.Decrypt(key, encr);
        }
    }
}
