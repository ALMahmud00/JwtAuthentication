using JwtAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthentication.Controllers
{
    [Route("auth/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        [HttpPost]
        [Route("Login")]
        public IActionResult Login(Credential credential)
        {
            var jwtAuthManager = new JwtAuthManager();
            var authResult = jwtAuthManager.Authenticate(credential.UserName, credential.Password);

            return Ok(authResult);
        }


        [HttpGet]
        [Route("UserInfo")]
        [Authorize]
        public IActionResult UserInfo()
        {
            var result = new { UserName = "admin", Password = "admin" };
            return Ok(result);
        }
    }
}
