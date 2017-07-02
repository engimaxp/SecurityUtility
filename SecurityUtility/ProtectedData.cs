using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityUtility
{
    public class ProtectedData
    {
        public string Guid { get; set; }
        public string Data { get; set; }
        public string Token { get; set; }
        public string Time { get; set; }
        public string Sign { get; set; }
    }
}
