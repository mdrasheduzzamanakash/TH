using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TH.Configurations;
using TH.Domains;
using TH.Services;
using TH.Services.Cache;

namespace TH.Middlewares
{
    public class RefreshTokenMiddleware
    {
        private readonly RequestDelegate _next;
        public RefreshTokenMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var jwt = context.Request.Cookies[THDefaults.Jwt];
            var refresh = context.Request.Cookies[THDefaults.Refresh];
            
            try
            {
                if (!context.User.IsInRole(THDefaults.Guest) && jwt != null && refresh != null && !IsAuthControllerRequest(context.Request.Path))
                {
                    var _jwtConfig = context.RequestServices.GetService<IOptionsMonitor<JwtConfig>>()?.CurrentValue;
                    var _cacheService = context.RequestServices.GetService<ICacheService>();
                    
                    // verification of jwt token 
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);
                    var tokenValidationParamerters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        RequireExpirationTime = true,
                        ValidateLifetime = false,
                        ClockSkew = TimeSpan.Zero
                    };

                    var principal = tokenHandler.ValidateToken(jwt, tokenValidationParamerters, out var validatedToken);

                    if (validatedToken is JwtSecurityToken jwtSecurityToken)
                    {
                        var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                        if (!result)
                        {
                            await context.SignOutAsync();
                            context.Response.Redirect(THDefaults.LoginUrl);
                            return;
                        }
                        var utcExpiryDate = long.Parse(principal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp)?.Value ?? "");
                        var expiryDate = UnixTimeStampToDate(utcExpiryDate);

                        if (expiryDate < DateTime.UtcNow)
                        {
                            string currentUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}";
                            context.Response.Cookies.Append(THDefaults.RedirectUrl, currentUrl);
                            context.Response.Redirect(THDefaults.TokenRefreshUrl);
                            return;
                        }

                        // now check if the user role has been changed 
                        // like after email has been verified from another device 
                        var email = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value ?? "";
                        var cache_key_check = new CacheKey(email, THDefaults.CacheTypeEmailJustVerified);
                        var cache_key_actual = new CacheKey(email, THDefaults.CacheTypeUserClaims);
                        if (email != null && _cacheService.ContainsKey(cache_key_check))
                        {
                            // update the role
                            var updatedClaims = _cacheService.Get(cache_key_actual) as List<Claim>;

                            #region HttpContext authentication 

                            // terminate previous session
                            await context.SignOutAsync();

                            var identity = new ClaimsIdentity(updatedClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                            var newPrincipal = new ClaimsPrincipal(identity);
                            var props = new AuthenticationProperties();

                            // start new session
                            context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, newPrincipal, props).Wait();

                            #endregion

                            // after one refresh the jwt and refresh token will be updated 
                            string currentUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}";
                            context.Response.Cookies.Append(THDefaults.RedirectUrl, currentUrl);
                            context.Response.Redirect(THDefaults.TokenRefreshUrl);
                            return;

                        }
                    }
                    else
                    {
                        await context.SignOutAsync();
                        context.Response.Redirect(THDefaults.LoginUrl);
                        return;
                    }
                }

            }
            catch (Exception ex)
            {
                var _logService = context.RequestServices.GetService<ILogService>();

                var _ = await _logService.InsertAsync(new Log
                {
                    Message = ex.Message,
                    Description = ex.ToString(),
                    Origin = "RefreshTokenMiddleware",
                    Tag = THDefaults.Urgent,
                    Type = THDefaults.Error
                });
            }
            await _next(context);
        }

        private bool IsAuthControllerRequest(string requestPath)
        {
            // Replace with the actual path to your AuthController
            var authControllerPath = "/Auth";

            return requestPath.StartsWith(authControllerPath, StringComparison.OrdinalIgnoreCase);
        }

        private DateTime UnixTimeStampToDate(long utcExpiryDate)
        {
            var dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(utcExpiryDate);
            return dateTime;
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
