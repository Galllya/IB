using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.IO;

namespace SimpleAsyncServerV2Security
{
    public class EncryptionAES
    {

        #region AES
        public byte[] EncryptDataBufferAES(byte[] UnencryptedMessage, ClientData client)
        {
            byte[] key = client.AesKey;
            byte[] IV = client.AesIV;
            if (UnencryptedMessage == null || UnencryptedMessage.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            using (Aes aesEnc = Aes.Create())
            {
                aesEnc.Key = key;
                aesEnc.IV = IV;
                aesEnc.Padding = PaddingMode.Zeros;
        
                using (var encryptor = aesEnc.CreateEncryptor(aesEnc.Key, aesEnc.IV))
                {
                    return PerformCryptogrphy(UnencryptedMessage, encryptor);
                }
            }
        }

        public byte[] DecryptDataBufferAES(byte[] EncryptedBuffer, ClientData client)
        {
            
            
            byte[] key = client.AesKey;
            byte[] IV = client.AesIV;

            if (EncryptedBuffer == null || EncryptedBuffer.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

           

            using (Aes aesDec = Aes.Create())
            {
                aesDec.Key = key;
                aesDec.IV = IV;
                aesDec.Padding = PaddingMode.Zeros;

            
                using (var decryptor = aesDec.CreateDecryptor(aesDec.Key, aesDec.IV))
                {
                    return PerformCryptogrphy(EncryptedBuffer, decryptor);
                }
            }
        }
        public byte[] PerformCryptogrphy(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }
        #endregion AES
    }
}
