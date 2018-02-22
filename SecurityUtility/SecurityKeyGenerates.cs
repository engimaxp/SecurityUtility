using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityUtility
{
    public class SecurityKeyGenerates
    {
        public static SecurityKeyPair Generate() {
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            //RSA密钥构造器的参数 
            RsaKeyGenerationParameters param = new RsaKeyGenerationParameters(
                Org.BouncyCastle.Math.BigInteger.ValueOf(3),
                new Org.BouncyCastle.Security.SecureRandom(),
                1024,   //密钥长度 
                25);
            //用参数初始化密钥构造器 
            generator.Init(param);
            //产生密钥对 
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            //获取公钥和密钥 
            AsymmetricKeyParameter publicKey = keyPair.Public;
            AsymmetricKeyParameter privateKey = keyPair.Private;
            if (((RsaKeyParameters)publicKey).Modulus.BitLength < 1024)
            {
                Console.WriteLine("failed key generation (1024) length test");
            }
            
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

            Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
            byte[] publicInfoByte = asn1ObjectPublic.GetEncoded();
            Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded();

            //这里可以将密钥对保存到本地  
            Console.WriteLine("PublicKey:\n" + Convert.ToBase64String(publicInfoByte));
            Console.WriteLine("PrivateKey:\n" + Convert.ToBase64String(privateInfoByte));

            return new SecurityKeyPair{
                RSAPublicKeyJava = Convert.ToBase64String(publicInfoByte),
                RSAPrivateKeyJava = Convert.ToBase64String(privateInfoByte)
            };
        }
        public static SecurityKeyPair GetSecurityKeyPair()
        {
            int count = 3;
            bool ckeck = false;
            SecurityKeyPair pair = null;
            while (count > 0)
            {
                pair = Generate();
                ckeck = TestKeyPair(pair);
                if(ckeck)break;
                count--;
            }
            return pair;
        }


        public static bool TestKeyPair(SecurityKeyPair pair)
        {
            if (pair == null) return false;
            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                string privateKeyNet = pair.RSAPrivateKeyJava.RSAPrivateKeyJava2DotNet();
                rsa.FromXmlString(privateKeyNet);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
    }
}
