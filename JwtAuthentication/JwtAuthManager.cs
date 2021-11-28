using JwtAuthentication.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthentication
{
    public class JwtAuthManager
    {
        public JwtAuthResponse Authenticate(string userName, string password)
        {
            //validate the username and password
            if (userName != "admin" || password != "admin")
            {
                throw new UnauthorizedAccessException("Unauthorize access denied!");
            }

            var tokenExpiryTimeStamp = DateTime.Now.AddMinutes(Constants.JWT_TOKEN_VALIDITY_MINS);
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(Constants.JWT_SECURITY_KEY);
            var securityTokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new List<Claim>
                {
                    new Claim("username", userName),
                    new Claim("author", "https://github.com/ALMahmud00"),
                    new Claim(ClaimTypes.PrimaryGroupSid, "Admin User Group")
                }),
                Expires = tokenExpiryTimeStamp,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
            };

            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);

            return new JwtAuthResponse()
            {
                UserName = userName,
                Token = token,
                ExpiresInSeconds = (long) tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds
            };

        }
    }
}
