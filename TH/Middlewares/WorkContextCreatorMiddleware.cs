using Microsoft.Extensions.Options;
using TH.Configurations;

namespace TH.Middlewares
{
    public class WorkContextCreatorMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly JwtConfig _jwtConfig;
        public WorkContextCreatorMiddleware(RequestDelegate next, 
            IOptionsMonitor<JwtConfig> optionsMonitor)
        {
            _next = next;
            _jwtConfig = optionsMonitor.CurrentValue;
        }


        public async Task InvokeAsync(HttpContext context)
        {
            // TODO 
            // decode the jwt token 

            // get the email from token 

            // get the user from cache 

            // assign the user as current user in workcontext
            await _next(context);
        }
    }


    public static class WorkContextCreatorMiddlewareExtension
    {
        public static IApplicationBuilder UseWorkContextCreatorMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<WorkContextCreatorMiddleware>();
        }
    }
}
