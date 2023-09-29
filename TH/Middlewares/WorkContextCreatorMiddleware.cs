using Microsoft.Extensions.Options;
using TH.Configurations;
using TH.Services;

namespace TH.Middlewares
{
    public class WorkContextCreatorMiddleware
    {
        private readonly RequestDelegate _next;
        public WorkContextCreatorMiddleware(RequestDelegate next)
        {
            _next = next;
        }


        public async Task InvokeAsync(HttpContext context)
        {
            var _workContext = context.RequestServices.GetService<IWorkContext>();
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
