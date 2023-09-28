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
            // Your custom token refresh logic goes here

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
