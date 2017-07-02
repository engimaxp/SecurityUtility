using System;
using NUnit.Framework;
using SecurityUtility;

namespace PlayGround
{
    [TestFixture]
    public class UnitTest1
    {
        [Test]
        public void ExaminGenerator()
        {
            var a = SecurityKeyGenerates.Generate();
            Assert.IsNotNull(a);

            var b = "HelloWorld!";
            var data = Security.RSAEncrypt2(a.RSAPublicKeyJava, b);
            var c = Security.RSADecrypt(a.RSAPrivateKeyJava.RSAPrivateKeyJava2DotNet(), data);
            Assert.AreEqual(b, c);
        }

        [Test]
        public void ExaminGeneratorLoadBalance()
        {
            var a = SecurityKeyGenerates.Generate();
            Assert.IsNotNull(a);
            for (int i = 0; i < 10000; i++)
            {
                var b = Security.CreateDESKey();
                var data = Security.RSAEncrypt2(a.RSAPublicKeyJava, b);
                var c = Security.RSADecrypt(a.RSAPrivateKeyJava.RSAPrivateKeyJava2DotNet(), data);
                Assert.AreEqual(b, c);
            }
        }
    }
}
