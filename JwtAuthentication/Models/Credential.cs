using System;

namespace JwtAuthentication.Models
{
    [Serializable]
    public class Credential
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}
