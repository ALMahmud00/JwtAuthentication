
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace JwtAuthentication
{
    public class RetrieveJwtInfoMiddleware
    {
        private readonly RequestDelegate _next;

        public RetrieveJwtInfoMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            httpContext.Items["some"] = "value";

            var authData = httpContext.Items["some"];
            //httpContext.Items["InfoVariable"] = "User Info";
            await _next(httpContext);
        }
    }
}
