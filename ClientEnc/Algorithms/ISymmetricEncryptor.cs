using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ClientEnc.Algorithms
{
    public interface ISymmetricEncryptor
    {
        string Encrypt(string key, string plaintext);
        string Decrypt(string key, string encoded);

    }
}
