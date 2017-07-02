using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace SecurityUtility
{
    public class SecurityCore
    {
        private const string MD5_URL_PARAM = "{0}{1}{2}";

        public const string MD5 = "Mke4aPAzTW4XCV42p43hiU1aBc2W7r7p";

        private SecurityKeyPair _key;
        public SecurityCore(SecurityKeyPair key)
        {
            _key = key;
        }

        /// <summary>
        /// 获取公钥
        /// </summary>
        /// <returns></returns>
        public string GetPublicKey()
        {
            return this._key.RSAPublicKeyJava;
        }

        /// <summary>
        /// 验证 MD5
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static bool MD5Verify(ProtectedData data)
        {
            string urlParam = string.Format(MD5_URL_PARAM, data.Data, data.Token, data.Time);

            if (Security.MD5Verify(data.Sign, urlParam, MD5))
            {
                return true;
            }
            else
            {
                //Logger.Warn(data, "MD5 校验失败，验证Sign：" + Security.MD5Encrypt(urlParam, MD5));

                return false;
            }
        }

        /// <summary>
        /// 解密源数据
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <returns></returns>
        public T GetSourceData<T>(ProtectedData data)
        {
            try
            {
                string desKey = Security.RSADecrypt(_key.RSAPrivateKeyJava.RSAPrivateKeyJava2DotNet(), data.Token);
                string sourceData = HttpUtility.UrlDecode(Security.DESDecrypt(data.Data, desKey), Encoding.UTF8);
                
                return JsonConvert.DeserializeObject<T>(sourceData);
            }
            catch (Exception ex)
            {
                //Logger.Warn(data, ex);
            }
            return default(T);
        }

        /// <summary>
        /// 加密数据
        /// </summary>
        /// <param name="sourceData">原数据</param>
        /// <returns></returns>
        public ProtectedData GetProtectedData(string sourceData)
        {
            try
            {
                string desKey = Security.CreateDESKey();
                ProtectedData data = new ProtectedData();

                data.Data = Security.DESEncrypt(sourceData, desKey);
                data.Token = Security.RSAEncrypt(this._key.RSAPrivateKeyJava, desKey);
                data.Time = DateTimeUtility.GetLinuxUTCTimeStamp();
                data.Sign = Security.MD5Encrypt(string.Format(MD5_URL_PARAM, data.Data, data.Token, data.Time), MD5);

                return data;
            }
            catch (Exception ex)
            {
                //Logger.Warn(ex);
            }

            return null;
        }
    }
}
