using Microsoft.Extensions.Options;
using TH.Configurations;

namespace TH.Middlewares
{
    public class RefreshTokenMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly JwtConfig _jwtConfig;
        public RefreshTokenMiddleware(RequestDelegate next, 
            IOptionsMonitor<JwtConfig> optionsMonitor)
        {
            _next = next;
            _jwtConfig = optionsMonitor.CurrentValue;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // TODO
            await _next(context);
        }

    }

    public static class RefreshTokenMiddlewareExtensions
    {
        public static IApplicationBuilder UseRefreshTokenMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<RefreshTokenMiddleware>();
        }
    }
}
