using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TH.Configurations;

namespace TH.Middlewares
{
    public class CheckForGuestMiddleware
    {
        private readonly RequestDelegate _next;
        public CheckForGuestMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var jwt = context.Request.Cookies[THDefaults.Jwt];
            var refresh = context.Request.Cookies[THDefaults.Refresh];

            if(jwt == null)
            {
                // assuming visitor as guest
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Role, THDefaults.Guest)
                };

                var identity = new ClaimsIdentity(authClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                var props = new AuthenticationProperties();
                context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props).Wait();
            } 
            // Call the next middleware in the pipeline
            await _next(context);
        }

    }

    public static class CheckForGuestMiddlewareExtension
    {
        public static IApplicationBuilder UseCheckForGuestMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<CheckForGuestMiddleware>();
        }
    }
}
