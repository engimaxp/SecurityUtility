using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityUtility
{
    public class DateTimeUtility
    {

        /// <summary>
        /// 获取 UTC 时间
        /// </summary>
        /// <param name="addHours">时区</param>
        /// <returns></returns>
        public static DateTime GetUTCTime(int addHours)
        {
            return DateTime.UtcNow.AddHours(addHours);
        }
        /// <summary>
        /// DateTime时间格式转换为Unix时间戳格式
        /// </summary>
        /// <param name='time'></param>
        /// <returns></returns>
        public static int ToLinuxTimeStamp(System.DateTime time)
        {
            System.DateTime startTime = TimeZone.CurrentTimeZone.ToLocalTime(new System.DateTime(1970, 1, 1));
            return (int)(time - startTime).TotalSeconds;
        }

        public static string GetLinuxUTCTimeStamp()
        {
            return ToLinuxTimeStamp(GetUTCTime(0)).ToString();
        }
    }
}
