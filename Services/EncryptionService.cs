using System.Security.Cryptography;
using System.Text;
using EncryptionWeb.Models;

namespace EncryptionWeb.Services
{
    public class EncryptionService
    {
        public EncryptionResult EncryptAes(string text)
        {
            byte[] key = RandomNumberGenerator.GetBytes(32);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] data = Encoding.UTF8.GetBytes(text);
            byte[] encrypted = new byte[data.Length];
            byte[] tag = new byte[16];

            using (AesGcm aes = new AesGcm(key, 16))
            {
                aes.Encrypt(nonce, data, encrypted, tag);
            }

            EncryptionResult result = new EncryptionResult();
            result.EncryptedText = Convert.ToBase64String(encrypted);
            result.DecryptedText = DecryptAes(encrypted, key, nonce, tag);
            return result;
        }

        private string DecryptAes(byte[] encrypted, byte[] key, byte[] nonce, byte[] tag)
        {
            byte[] decrypted = new byte[encrypted.Length];
            using (AesGcm aes = new AesGcm(key, 16))
            {
                aes.Decrypt(nonce, encrypted, tag, decrypted);
            }
            return Encoding.UTF8.GetString(decrypted);
        }

        public EncryptionResult EncryptRsa(string text)
        {
            using (RSA rsa = RSA.Create(2048))
            {
                byte[] data = Encoding.UTF8.GetBytes(text);
                byte[] encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

                EncryptionResult result = new EncryptionResult();
                result.EncryptedText = Convert.ToBase64String(encrypted);
                result.DecryptedText = DecryptRsa(encrypted, rsa);
                return result;
            }
        }

        private string DecryptRsa(byte[] encrypted, RSA rsa)
        {
            byte[] decrypted = rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decrypted);
        }
    }
}
