using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtAuthentication.Models
{
    [Serializable]
    public class JwtAuthResponse
    {
        public string Token { get; set; }
        public string UserName { get; set; }
        public long ExpiresInSeconds { get; set; }
    }
}
