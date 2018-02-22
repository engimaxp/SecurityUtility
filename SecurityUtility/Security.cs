using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityUtility
{
    public class Security
    {
        private const string ENCODING_STRING = "UTF-8";

        private const string RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="privateKeyNet">.Net 私钥</param>
        /// <param name="content"></param>
        /// <returns></returns>
        public static string RSADecrypt(string privateKeyNet, string data, string encoding = ENCODING_STRING)
        {
            RSACryptoServiceProvider.UseMachineKeyStore = true;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            byte[] cipherbytes;
            rsa.FromXmlString(privateKeyNet);

            //RSAEncryptionPadding padding = RSAEncryptionPadding.CreateOaep(new System.Security.Cryptography.HashAlgorithmName(hashAlgorithm));
            //cipherbytes = rsa.Decrypt(Encoding.GetEncoding(encoding).GetBytes(data), padding);

            cipherbytes = rsa.Decrypt(Convert.FromBase64String(data), false);

            return Encoding.GetEncoding(encoding).GetString(cipherbytes);
        }
        /// <summary>
        /// RSA私钥加密 (For Java)
        /// </summary>
        /// <param name="publicKeyJava">Java 私钥</param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string RSAEncrypt(string privateKeyJava, string data, string encoding = ENCODING_STRING)
        {
            RsaKeyParameters privateKeyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKeyJava));
            var cipher = CipherUtilities.GetCipher(RSA_ALGORITHM);

            byte[] cipherbytes = Encoding.GetEncoding(encoding).GetBytes(data);
            cipher.Init(true, privateKeyParam);
            cipherbytes = cipher.DoFinal(cipherbytes, 0, cipherbytes.Length);
            return Convert.ToBase64String(cipherbytes);
        }

        /// <summary>
        /// RSA公钥加密 (For Java)
        /// </summary>
        /// <param name="publicKeyJava">Java 公钥</param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string RSAEncrypt2(string publicKeyJava, string data, string encoding = ENCODING_STRING)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKeyJava));
            var cipher = CipherUtilities.GetCipher(RSA_ALGORITHM);

            byte[] cipherbytes = Encoding.GetEncoding(encoding).GetBytes(data);
            cipher.Init(true, publicKeyParam);
            cipherbytes = cipher.DoFinal(cipherbytes, 0, cipherbytes.Length);
            return Convert.ToBase64String(cipherbytes);
        }

        /// <summary>
        /// DES 加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>

        public static string DESEncrypt(string data, string key, string encoding = ENCODING_STRING)
        {
            DESCryptoServiceProvider provider = new DESCryptoServiceProvider();
            provider.Key = Encoding.ASCII.GetBytes(key.Substring(0, 8));
            provider.IV = Encoding.ASCII.GetBytes(key.Substring(0, 8));
            byte[] bytes = Encoding.GetEncoding(encoding).GetBytes(data);
            MemoryStream stream = new MemoryStream();
            CryptoStream stream2 = new CryptoStream(stream, provider.CreateEncryptor(), CryptoStreamMode.Write);
            stream2.Write(bytes, 0, bytes.Length);
            stream2.FlushFinalBlock();
            StringBuilder builder = new StringBuilder();
            foreach (byte num in stream.ToArray())
            {
                builder.AppendFormat("{0:X2}", num);
            }
            stream.Close();
            return builder.ToString();
        }

        /// <summary>
        /// DES 解密
        /// </summary>
        /// <param name="str"></param>
        /// <param name="key"></param>
        /// <returns></returns>

        public static string DESDecrypt(string data, string key, string encoding = ENCODING_STRING)
        {
            DESCryptoServiceProvider provider = new DESCryptoServiceProvider();

            provider.Key = Encoding.ASCII.GetBytes(key.Substring(0, 8));
            provider.IV = Encoding.ASCII.GetBytes(key.Substring(0, 8));
            byte[] buffer = new byte[data.Length / 2];
            for (int i = 0; i < (data.Length / 2); i++)
            {
                int num2 = Convert.ToInt32(data.Substring(i * 2, 2), 0x10);
                buffer[i] = (byte)num2;
            }
            MemoryStream stream = new MemoryStream();
            CryptoStream stream2 = new CryptoStream(stream, provider.CreateDecryptor(), CryptoStreamMode.Write);
            stream2.Write(buffer, 0, buffer.Length);
            stream2.FlushFinalBlock();
            stream.Close();
            return Encoding.GetEncoding(encoding).GetString(stream.ToArray());
        }


        /// <summary>
        /// MD5 签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string MD5Encrypt(string data, string key, string encoding = ENCODING_STRING)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] t = md5.ComputeHash(Encoding.GetEncoding(ENCODING_STRING).GetBytes(data + key));
            StringBuilder sb = new StringBuilder(32);
            for (int i = 0; i < t.Length; i++)
            {
                sb.Append(t[i].ToString("x").PadLeft(2, '0'));
            }

            return sb.ToString();
        }

        /// <summary>
        /// MD5 验签
        /// </summary>
        /// <param name="sign"></param>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static bool MD5Verify(string sign, string data, string key, string encoding = ENCODING_STRING)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] t = md5.ComputeHash(Encoding.GetEncoding(ENCODING_STRING).GetBytes(data + key));
            StringBuilder sb = new StringBuilder(32);
            for (int i = 0; i < t.Length; i++)
            {
                sb.Append(t[i].ToString("x").PadLeft(2, '0'));
            }

            return sign == sb.ToString();
        }

        /// <summary>
        /// 创建随机 DES Key
        /// </summary>
        /// <returns></returns>
        public static string CreateDESKey()
        {
            string so = "TYSDpqonHJKL0ZF9uts8GPAzQW4XCVvwxg4i2Udabc2E7r6yRI8OjklmdefBNM";

            Random rand = new Random(DateTime.Now.Millisecond);
            string str = null;
            for (int i = 0; i < 8; i++)
            {
                str += so.Substring(rand.Next(62), 1);
            }

            return str;
        }
    }
}
