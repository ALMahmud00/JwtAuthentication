using JwtAuthentication.Models;
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
    }
}
