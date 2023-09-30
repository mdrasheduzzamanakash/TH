using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Security.Claims;
using TH.Configurations;
using TH.Domains;
using TH.Services;
using TH.Services.Cache;

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
            try
            {
                var _workContext = context.RequestServices.GetService<IWorkContext>();
                var _customerService = context.RequestServices.GetService<ICustomerService>();
                var _cacheService = context.RequestServices.GetService<ICacheService>();

                var email = context.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value ?? DateTime.UtcNow.Ticks.ToString();

                var parameters = new List<object> { email };
                var customer = await _cacheService.GetOrSet(new CacheKey(email, THDefaults.CacheTypeCustomer), async (parameters) =>
                {
                    var customer = await _customerService.FindByEmailAsync(email: parameters[0].ToString() ?? "");
                    if (customer == null)
                    {
                        return new object();
                    }
                    return customer;
                }, TimeSpan.FromMinutes(60), parameters);

                if (customer is Customer && _workContext != null)
                {
                    var roles = context.User.Claims.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value).ToList();
                    _workContext.SetCurrentCustomer((Customer)customer);
                    _workContext.SetCurrentCustomerRoles(roles);
                }
            } 
            catch (Exception ex)
            {
                var _logService = context.RequestServices.GetService<ILogService>();
                if(_logService != null)
                {
                    var _ = await _logService.InsertAsync(new Log
                    {
                        Message = ex.Message,
                        Description = ex.ToString(),
                        Origin = "WorkContextCreatorMiddleware",
                        Tag = THDefaults.Urgent,
                        Type = THDefaults.Error
                    });
                }
            }

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
