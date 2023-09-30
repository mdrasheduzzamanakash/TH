using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Policy;
using System.Text;
using TH.Configurations;
using TH.Domains;
using TH.Models;
using TH.Services;
using TH.Services.Cache;
using TH.Services.ThirdPartyServices;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;

namespace TH.Controllers
{
    
    public class AuthController : Controller
    {
        #region Fields
        private readonly ICustomerService _customerService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly JwtConfig _jwtConfig;
        private readonly IRefreshTokenService _refreshTokenService;
        private readonly ILogService _logService;
        private readonly IEmailService _emailService;
        private readonly ICacheService _cacheService;
        #endregion

        #region Ctor
        public AuthController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IOptionsMonitor<JwtConfig> optionMonitor,
            ICustomerService customerService,
            IRefreshTokenService refreshTokenService,
            ILogService logService, 
            IEmailService emailService, 
            ICacheService cacheService)
        {
            _cacheService = cacheService;
            _emailService = emailService;
            _logService = logService;
            _refreshTokenService = refreshTokenService;
            _customerService = customerService;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _jwtConfig = optionMonitor.CurrentValue;
        }

        #endregion

        #region Utilities 

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.Secret));
            var token = new JwtSecurityToken(
                    issuer: _jwtConfig.ValidIssuer,
                    audience: _jwtConfig.ValidAudience,
                    expires: DateTime.UtcNow.Add(_jwtConfig.ExpiryTimeFrame),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, THDefaults.jwtAlgo)
                );
            return token;
        }

        private string RandomStringGenerator(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private DateTime UnixTimeStampToDate(long utcExpiryDate)
        {
            var dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(utcExpiryDate);
            return dateTime;
        }

        #endregion

        #region Login / Logout

        [Authorize(Roles = THDefaults.Guest)]
        public IActionResult Login()
        {
            return View(new LoginModel());
        }


        [Authorize(Roles = THDefaults.Guest)]
        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                ViewData["Error"] = "Problem logging in, try again later.";
                return View(model);
            }

            var welcomeName = "";

            try
            {
                // get the customer
                var customer = await _customerService.FindByEmailAsync(model.Email);

                // get the identity user
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null && customer != null && await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, model.Email),
                        new Claim(ClaimTypes.Email, model.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };

                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    #region Application wise token 


                    // create a token as current role
                    var jwtToken = GetToken(authClaims);
                    var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);


                    // create referesh token 
                    var jti = jwtToken.Claims.Where(claim => claim.Type == JwtRegisteredClaimNames.Jti).FirstOrDefault()?.Value;
                    var refreshToken = new RefreshToken
                    {
                        Token = $"{RandomStringGenerator(50)}_{Guid.NewGuid()}",
                        CustomerId = customer.Id,
                        IdentityId = user.Id,
                        IsUsed = false,
                        IsExpired = false,
                        IsRevoked = false,
                        ExpiryDate = DateTime.UtcNow.AddDays(30),
                        JwtId = jti ?? ""
                    };

                    // save the refresh token 
                    var _ = await _refreshTokenService.InsertAsync(refreshToken);

                    // add cookies
                    var jwtTokenCookieOptions = new CookieOptions
                    {
                        HttpOnly = false,
                        Expires = DateTime.UtcNow.AddMonths(1),
                    };
                    Response.Cookies.Append(THDefaults.Jwt, token, jwtTokenCookieOptions);

                    var refreshTokenCookieOptions = new CookieOptions
                    {
                        HttpOnly = true,
                        Expires = DateTime.UtcNow.AddMonths(1)
                    };
                    Response.Cookies.Append(THDefaults.Refresh, refreshToken.Token, refreshTokenCookieOptions);

                    #endregion


                    #region HttpContext authentication 
                    // terminate previous session
                    await HttpContext.SignOutAsync();

                    var identity = new ClaimsIdentity(authClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);
                    var props = new AuthenticationProperties();
                    
                    // start new session
                    HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props).Wait();

                    #endregion

                    // set global values 
                    welcomeName = customer.FirstName + " " + customer.LastName;

                } else
                {
                    var _ = await _logService.InsertAsync(new Log
                    {
                        Message = "User unable to login",
                        Description = "User unable to login",
                        Origin = ControllerContext.ActionDescriptor.ControllerName + "_" + ControllerContext.ActionDescriptor.ActionName,
                        Tag = THDefaults.Urgent,
                        Type = THDefaults.Error
                    });

                    ViewData["Error"] = "Problem logging in, try again later.";
                    return View(model);
                }
            }
            catch (Exception ex)
            {
                var _ = await _logService.InsertAsync(new Log
                {
                    Message = ex.Message,
                    Description = ex.ToString(),
                    Origin = ControllerContext.ActionDescriptor.ControllerName + "_" + ControllerContext.ActionDescriptor.ActionName,
                    Tag = THDefaults.Urgent,
                    Type = THDefaults.Error
                });
            }
            Response.Cookies.Append(THDefaults.OTMActive, THDefaults.Active);
            Response.Cookies.Append(THDefaults.OneTimeMessage, "Welcome Back! " + welcomeName);
            return RedirectToAction("Index", "Home");
        }


        [Authorize(Roles =
            THDefaults.DoctorUnverified + "," +
            THDefaults.PatientUnverified + "," +
            THDefaults.Doctor + "," +
            THDefaults.Patient)]
        public async Task<IActionResult> Logout()
        {
            Response.Cookies.Delete(THDefaults.OneTimeMessage);
            Response.Cookies.Delete(THDefaults.Jwt);
            Response.Cookies.Delete(THDefaults.Refresh);

            await HttpContext.SignOutAsync();

            return RedirectToAction("Index", "Home");
        }

        [AllowAnonymous]
        public async Task<IActionResult> AccessDenied(string returnUrl)
        {
            return Ok("hi");
        }

        #endregion

        #region Register


        [Authorize(Roles = THDefaults.Guest)]
        public IActionResult Register()
        {
            return View(new RegisterModel());
        }


        [Authorize(Roles = THDefaults.Guest)]
        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel model, string role)
        {
            // Check model validation 
            if (!ModelState.IsValid)
            {
                ViewData["Error"] = "Problem registering in, Please provide information accordingly";
                return View(model);
            }

            try
            {
                var welcomeName = "";

                // Check user exist 
                var userExist = await _userManager.FindByEmailAsync(model.Email);
                if (userExist != null)
                {
                    ViewData["Error"] = "Email already exists, try login.";
                    return View(model);
                }

                // Add User to db
                var user = new IdentityUser
                {
                    Email = model.Email,
                    UserName = model.Email,
                    SecurityStamp = Guid.NewGuid().ToString()
                };

                var roleExist = await _roleManager.RoleExistsAsync(role);
                if (roleExist &&
                    role != THDefaults.Admin &&
                    role != THDefaults.Doctor &&
                    role != THDefaults.Patient &&
                    (role == THDefaults.DoctorUnverified || role == THDefaults.PatientUnverified))
                {
                    var result = await _userManager.CreateAsync(user, model.Password);

                    // now create the customer 
                    var customer = new Customer
                    {
                        FirstName = model.FirstName,
                        LastName = model.LastName,
                        Email = model.Email,
                        IdentityId = user.Id,
                        OnRole = role
                    };

                    var customerResult = await _customerService.InsertAsync(customer);

                    if (!result.Succeeded || customerResult == null)
                    {
                        var errorMessages = string.Join("<br />", result.Errors.Select(e => e.Description));
                        ViewData["Error"] = errorMessages;
                        return View(model);
                    }

                    await _userManager.AddToRoleAsync(user, role);

                    // Add token to verify the email 
                    var baseUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}";
                    var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { emailToken, email = user.Email }, protocol: HttpContext.Request.Scheme, host: HttpContext.Request.Host.ToString());

                    // send the email 
                    await _emailService.SendAccountVerificationMailAsync(user.Email, confirmationLink ?? "", new Dictionary<string, string>
                    {
                        ["Name"] = customer.FirstName
                    });

                    // create jwt token 
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, model.Email),
                        new Claim(ClaimTypes.Email, model.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };

                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var eachrole in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, eachrole));
                    }

                    #region Application wise token

                    var jwtToken = GetToken(authClaims);
                    var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);

                    // create a token as RegisteredUnvarified role
                    var jti = jwtToken.Claims.Where(claim => claim.Type == JwtRegisteredClaimNames.Jti).FirstOrDefault()?.Value;
                    var refreshToken = new RefreshToken
                    {
                        Token = $"{RandomStringGenerator(50)}_{Guid.NewGuid()}",
                        CustomerId = customerResult.Id,
                        IdentityId = user.Id,
                        IsUsed = false,
                        IsRevoked = false,
                        IsExpired = false,
                        ExpiryDate = DateTime.UtcNow.AddDays(30),
                        JwtId = jti ?? ""
                    };

                    var _ = await _refreshTokenService.InsertAsync(refreshToken);

                    // set cookies 
                    var jwtTokenCookieOptions = new CookieOptions
                    {
                        HttpOnly = false,
                        Expires = DateTime.UtcNow.AddMonths(1),
                    };
                    Response.Cookies.Append(THDefaults.Jwt, token, jwtTokenCookieOptions);

                    var refreshTokenCookieOptions = new CookieOptions
                    {
                        HttpOnly = true,
                        Expires = DateTime.UtcNow.AddMonths(1)
                    };
                    Response.Cookies.Append(THDefaults.Refresh, refreshToken.Token, refreshTokenCookieOptions);


                    #endregion

                    #region HttpContext authentication 

                    // terminate previous session
                    await HttpContext.SignOutAsync();
                    
                    var identity = new ClaimsIdentity(authClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var principal = new ClaimsPrincipal(identity);
                    var props = new AuthenticationProperties();
                    
                    // start new session
                    HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props).Wait();

                    #endregion

                    Response.Cookies.Append(THDefaults.OTMActive, THDefaults.Active);
                    Response.Cookies.Append(THDefaults.OneTimeMessage, "Welcome, " + welcomeName + "! A confirmation link is sent to the mail. Please verify your email.");
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ViewData["Error"] = "The role is not valid.";
                    return View(model);
                }

            }
            catch (Exception ex)
            {
                var _ = await _logService.InsertAsync(new Log
                {
                    Message = ex.Message,
                    Description = ex.ToString(),
                    Origin = ControllerContext.ActionDescriptor.ControllerName + "_" + ControllerContext.ActionDescriptor.ActionName,
                    Tag = THDefaults.Urgent,
                    Type = THDefaults.Error
                });

                ViewData["Error"] = "Problem registering in, try again later.";
                return View(model);
            }
        }

        [HttpGet]
        [Route("Authentication/ConfirmEmail")]
        [Authorize(Roles = 
            THDefaults.DoctorUnverified + "," +
            THDefaults.PatientUnverified + "," +
            THDefaults.Guest)]
        public async Task<IActionResult> ConfirmEmail(string emailToken, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, emailToken);
                if (result.Succeeded)
                {
                    var customer = await _customerService.FindByEmailAsync(email);
                    
                    if (customer != null)
                    {
                        // remove the previous unvarified role 
                        await _userManager.RemoveFromRoleAsync(user, customer.OnRole);

                        // update the customer 
                        customer.OnRole = customer.OnRole == THDefaults.DoctorUnverified ? THDefaults.Doctor : THDefaults.Patient;
                        await _customerService.UpdateAsync(customer, customer.Id);

                        // Update role of the identity user 
                        await _userManager.AddToRoleAsync(user, customer.OnRole);

                        /*
                        // create jwt token 
                        var authClaims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, email),
                            new Claim(ClaimTypes.Email, email),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                            new Claim(ClaimTypes.Role, customer.OnRole == THDefaults.DoctorUnverified ? THDefaults.Doctor : THDefaults.Patient)
                        };

                        #region HttpContext authentication 

                        // terminate previous session
                        await HttpContext.SignOutAsync();

                        var identity = new ClaimsIdentity(authClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var principal = new ClaimsPrincipal(identity);
                        var props = new AuthenticationProperties();
                        
                        // start new session
                        HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props).Wait();

                        #endregion

                        #region Application wise token 

                        var jwtToken = GetToken(authClaims);
                        var jwtTokenString = new JwtSecurityTokenHandler().WriteToken(jwtToken);

                        // clear the previous role refresh token 
                        var prevRefreshToken = await _refreshTokenService.FindByIdentityIdAsync(user.Id);
                        if (prevRefreshToken != null)
                        {
                            await _refreshTokenService.DeleteAsync(prevRefreshToken.Id);
                        }

                        // create a token as verified role role
                        var jti = jwtToken.Claims.Where(claim => claim.Type == JwtRegisteredClaimNames.Jti).FirstOrDefault()?.Value;
                        var refreshToken = new RefreshToken
                        {
                            Token = $"{RandomStringGenerator(50)}_{Guid.NewGuid()}",
                            CustomerId = customer.Id,
                            IdentityId = user.Id,
                            IsUsed = false,
                            IsRevoked = false,
                            IsExpired = false,
                            ExpiryDate = DateTime.UtcNow.AddDays(30),
                            JwtId = jti ?? ""
                        };

                        var _ = await _refreshTokenService.InsertAsync(refreshToken);

                        // set cookies 
                        var jwtTokenCookieOptions = new CookieOptions
                        {
                            HttpOnly = false,
                            Expires = DateTime.UtcNow.AddMonths(1),
                        };
                        Response.Cookies.Append(THDefaults.Jwt, emailToken, jwtTokenCookieOptions);

                        var refreshTokenCookieOptions = new CookieOptions
                        {
                            HttpOnly = true,
                            Expires = DateTime.UtcNow.AddMonths(1)
                        };
                        Response.Cookies.Append(THDefaults.Refresh, refreshToken.Token, refreshTokenCookieOptions);


                        #endregion

                        */


                        #region Caching

                        _cacheService.Set(new CacheKey(email, THDefaults.CacheTypeEmailJustVerified), true, _jwtConfig.ExpiryTimeFrame.Add(TimeSpan.FromMinutes(5)));

                        #endregion


                        var model = new ConfirmEmailModel
                        {
                            Email = email,
                            Message = "Email verification successfull."
                        };
                        //TODO create a page
                        return Ok("Verification done");
                    }
                    else
                    {
                        var model = new ConfirmEmailModel
                        {
                            Email = email,
                            Message = "Unable to validate! Please register again."
                        };
                        return View(model);
                    }
                } else
                {
                    var model = new ConfirmEmailModel
                    {
                        Email = email,
                        Message = "Unable to validate! Please register again."
                    };
                    return View(model);
                }
            }
            else
            {
                var model = new ConfirmEmailModel
                {
                    Email = email,
                    Message = "Unable to validate! Please register again."
                };
                return View(model);
            }

        }

        #endregion

        #region Reset Password / Refresh Token

        [Authorize(Roles = THDefaults.Guest)]
        public IActionResult ForgotPassword()
        {
            return View(new ForgotPasswordModel ());
        }

        [Authorize(Roles = THDefaults.Guest)]
        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if(ModelState.IsValid)
            {
                // generate password reset token 
                var user = await _userManager.FindByEmailAsync(model.Email);
                if(user != null)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var forgotPasswordLink = Url.Action("ResetPassword", "Auth", new { token, email = user.Email }, protocol: HttpContext.Request.Scheme, host: HttpContext.Request.Host.ToString());

                    // TODO : send the email

                    Response.Cookies.Append(THDefaults.OTMActive, THDefaults.Active);
                    Response.Cookies.Append(THDefaults.OneTimeMessage, "A mail is sent to the " + model.Email + " with the proper instructions.");
                    return RedirectToAction("Login");
                } 
                else
                {
                    Response.Cookies.Append(THDefaults.OTMActive, THDefaults.Active);
                    Response.Cookies.Append(THDefaults.OneTimeMessage, model.Email + " is not registered. Please register first.");
                    return RedirectToAction("Register");
                }
            }
            
            return View(model);
        }

        [Authorize(Roles = THDefaults.Guest)]
        [HttpGet("reset-password")]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPasswordModel { Token = token, Email = email };
            return View(model);
        }

        [Authorize(Roles = THDefaults.Guest)]
        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if(user != null)
                {
                    var resetPassResult = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                    if (!resetPassResult.Succeeded)
                    {
                        var errorMessages = string.Join("<br />", resetPassResult.Errors.Select(e => e.Description));
                        ViewData["Error"] = errorMessages;
                        return View(model);
                    } 
                    else
                    {
                        Response.Cookies.Append(THDefaults.OTMActive, THDefaults.Active);
                        Response.Cookies.Append(THDefaults.OneTimeMessage, "Password reset successfull. Please login now.");
                        return RedirectToAction("Login");
                    }
                } 
                else
                {
                    return RedirectToAction("Login");
                }
            }
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken()
        {
            var jwt = Request.Cookies[THDefaults.Jwt];
            var refresh = Request.Cookies[THDefaults.Refresh];
            var redirectUrl = Request.Cookies[THDefaults.RedirectUrl];

            if (jwt == null || refresh == null || redirectUrl == null)
            {
                return RedirectToAction("Login");
            }

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

            try
            {
                var principal = tokenHandler.ValidateToken(jwt, tokenValidationParamerters, out var validatedToken);

                // check actual jwt token 
                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                    if (!result)
                    {
                        return RedirectToAction("Login");
                    }
                    var utcExpiryDate = long.Parse(principal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp)?.Value ?? "");
                    var expiryDate = UnixTimeStampToDate(utcExpiryDate);
                    
                    var email = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value ?? "";
                    var cache_key_check = new CacheKey(email, THDefaults.CacheTypeEmailJustVerified);

                    // check the exiry date of the jwt token 
                    if (expiryDate < DateTime.UtcNow || _cacheService.ContainsKey(cache_key_check))
                    {
                        // first remove the key 
                        _cacheService.Delete(cache_key_check);

                        var user = await _userManager.FindByEmailAsync(email);

                        if(user == null)
                        {
                            Response.Cookies.Delete(THDefaults.Jwt);
                            Response.Cookies.Delete(THDefaults.Refresh);

                            await HttpContext.SignOutAsync();

                            return RedirectToAction("Register");
                        }

                        // no refresh token available
                        var refreshToken = await _refreshTokenService.FindByIdentityIdAsync(user.Id);
                        if (refreshToken is null)
                        {
                            Response.Cookies.Delete(THDefaults.Jwt);
                            Response.Cookies.Delete(THDefaults.Refresh);

                            await HttpContext.SignOutAsync();

                            return RedirectToAction("Login");
                        }
                        
                        // check the expiry date
                        if (refreshToken.ExpiryDate < DateTime.UtcNow)
                        {
                            refreshToken.IsExpired = true;
                            await _refreshTokenService.UpdateAsync(refreshToken, refreshToken.Id);

                            Response.Cookies.Delete(THDefaults.Jwt);
                            Response.Cookies.Delete(THDefaults.Refresh);

                            await HttpContext.SignOutAsync();

                            return RedirectToAction("Login");
                        }

                        // check if the refresh token is used or not 
                        if (refreshToken.IsUsed)
                        {
                            Response.Cookies.Delete(THDefaults.Jwt);
                            Response.Cookies.Delete(THDefaults.Refresh);

                            await HttpContext.SignOutAsync();

                            return RedirectToAction("Login");
                        }

                        // check if the refresh token is revoked or not 
                        if (refreshToken.IsRevoked)
                        {
                            Response.Cookies.Delete(THDefaults.Jwt);
                            Response.Cookies.Delete(THDefaults.Refresh);

                            await HttpContext.SignOutAsync();

                            return RedirectToAction("Login");
                        }

                        // match the jwt refrence
                        var jti = principal.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)?.Value ?? "";
                        if (refreshToken.JwtId != jti)
                        {
                            refreshToken.IsRevoked = true;
                            await _refreshTokenService.UpdateAsync(refreshToken, refreshToken.Id);

                            Response.Cookies.Delete(THDefaults.Jwt);
                            Response.Cookies.Delete(THDefaults.Refresh);

                            await HttpContext.SignOutAsync();

                            return RedirectToAction("Login");
                        }

                        // the process come this far 
                        // create new refresh token and jwt token 
                        refreshToken.IsUsed = true;
                        await _refreshTokenService.UpdateAsync(refreshToken, refreshToken.Id);

                        var authClaims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, user?.Email ?? ""),
                            new Claim(ClaimTypes.Email, user?.Email ?? ""),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                        };

                        var userRoles = await _userManager.GetRolesAsync(user);
                        foreach (var role in userRoles)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, role));
                        }


                        #region HttpContext authentication 
                        // terminate previous session
                        await HttpContext.SignOutAsync();

                        var identity = new ClaimsIdentity(authClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                        var principal_ctx = new ClaimsPrincipal(identity);
                        var props = new AuthenticationProperties();
                        
                        // start new session
                        HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal_ctx, props).Wait();

                        #endregion

                        #region Application wise token 


                        // get the customer 
                        var customer = await _customerService.FindByEmailAsync(user.Email);

                        // create a token as current role
                        var jwtToken = GetToken(authClaims);
                        var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);

                        // create referesh token 
                        var newJti = jwtToken.Claims.Where(claim => claim.Type == JwtRegisteredClaimNames.Jti).FirstOrDefault()?.Value;
                        var newRefreshToken = new RefreshToken
                        {
                            Token = $"{RandomStringGenerator(50)}_{Guid.NewGuid()}",
                            CustomerId = customer?.Id ?? "",
                            IdentityId = user.Id,
                            IsUsed = false,
                            IsExpired = false,
                            IsRevoked = false,
                            ExpiryDate = DateTime.UtcNow.AddDays(30),
                            JwtId = newJti ?? ""
                        };

                        // save the refresh token 
                        var _ = await _refreshTokenService.InsertAsync(newRefreshToken);

                        // add cookies
                        var jwtTokenCookieOptions = new CookieOptions
                        {
                            HttpOnly = false,
                            Expires = DateTime.UtcNow.AddMonths(1),
                        };
                        Response.Cookies.Append(THDefaults.Jwt, token, jwtTokenCookieOptions);

                        var refreshTokenCookieOptions = new CookieOptions
                        {
                            HttpOnly = true,
                            Expires = DateTime.UtcNow.AddMonths(1)
                        };
                        Response.Cookies.Append(THDefaults.Refresh, newRefreshToken.Token, refreshTokenCookieOptions);


                        #endregion


                        // redirect to where it came from 
                        var defaultUrl = Url.Action("Index", "Home", new { }, protocol: HttpContext.Request.Scheme, host: HttpContext.Request.Host.ToString()) ?? "";
                        return Redirect(Request.Cookies[THDefaults.RedirectUrl] ?? defaultUrl);
                    }
                    else
                    {
                        var user = await _userManager.FindByEmailAsync(email);

                        if (user == null)
                        {
                            Response.Cookies.Delete(THDefaults.Jwt);
                            Response.Cookies.Delete(THDefaults.Refresh);

                            await HttpContext.SignOutAsync();

                            return RedirectToAction("Register");
                        }

                        // no refresh token available
                        var refreshToken = await _refreshTokenService.FindByIdentityIdAsync(user.Id);
                        if (refreshToken is null)
                        {
                            Response.Cookies.Delete(THDefaults.Jwt);
                            Response.Cookies.Delete(THDefaults.Refresh);

                            await HttpContext.SignOutAsync();

                            return RedirectToAction("Login");
                        }

                        refreshToken.IsRevoked = true;
                        await _refreshTokenService.UpdateAsync(refreshToken, refreshToken.Id);

                        Response.Cookies.Delete(THDefaults.Jwt);
                        Response.Cookies.Delete(THDefaults.Refresh);

                        await HttpContext.SignOutAsync();

                        return RedirectToAction("Login");
                    }
                } 
                else
                {
                    Response.Cookies.Delete(THDefaults.Jwt);
                    Response.Cookies.Delete(THDefaults.Refresh);

                    await HttpContext.SignOutAsync();

                    return RedirectToAction("Login");
                }
            }
            catch (Exception ex)
            {
                var _ = await _logService.InsertAsync(new Log
                {
                    Message = ex.Message,
                    Description = ex.ToString(),
                    Origin = ControllerContext.ActionDescriptor.ControllerName + "_" + ControllerContext.ActionDescriptor.ActionName,
                    Tag = THDefaults.Urgent,
                    Type = THDefaults.Error
                });

                Response.Cookies.Delete(THDefaults.Jwt);
                Response.Cookies.Delete(THDefaults.Refresh);

                await HttpContext.SignOutAsync();

                return RedirectToAction("Login");
            }
        }

        #endregion
    }

}
