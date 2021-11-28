using JwtAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace JwtAuthentication.Controllers
{
    [Route("auth/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        [HttpPost]
        [AllowAnonymous]
        [Route("Login")]
        public IActionResult Login(Credential credential)
        {
            var jwtAuthManager = new JwtAuthManager();
            var authResult = jwtAuthManager.Authenticate(credential.UserName, credential.Password);

            return Ok(authResult);
        }


        [HttpGet]
        [Route("UserInfo")]
        public IActionResult UserInfo()
        {
            var result = new { UserName = "admin", Password = "admin" };
            return Ok(result);
        }

        [HttpGet]
        [Route("RetrieveInfoFromJWT")]
        public IActionResult UserInfoFromJWT()
        {
            var result = new { Author = this.User.Claims.First(i => i.Type == "author").Value };
            return Ok(result);
        }
    }
}
