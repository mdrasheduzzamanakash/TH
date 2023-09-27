﻿using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TH.Configurations;
using TH.Domains;
using TH.Models;
using TH.Services;
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
        #endregion

        #region Ctor
        public AuthController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IOptionsMonitor<JwtConfig> optionMonitor, 
            ICustomerService customerService, 
            IRefreshTokenService refreshTokenService, 
            ILogService logService)
        {
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
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }

        private string RandomStringGenerator(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        #endregion

        #region Login / Logout
        public IActionResult Login()
        {
            return View(new LoginModel());
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if(!ModelState.IsValid)
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
                        IsRevoked = false,
                        ExpiryDate = DateTime.UtcNow.AddDays(30),
                        JwtId = jti ?? ""
                    };

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
            Response.Cookies.Append(THDefaults.OneTimeMessage, "Welcome Back! " + welcomeName);
            return RedirectToAction("Index", "Home");
        }

        public IActionResult Logout()
        {
            // TODO : clear the cookies 
            Response.Cookies.Delete(THDefaults.OneTimeMessage);
            Response.Cookies.Delete(THDefaults.Jwt);
            Response.Cookies.Delete(THDefaults.Refresh);

            return RedirectToAction("Index", "Home");
        }

        #endregion

        #region Register

        public IActionResult Register()
        {
            return View(new RegisterModel());
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel model, string role)
        {
            // Check model validation 
            if(!ModelState.IsValid)
            {
                ViewData["Error"] = "Problem registering in, try again later.";
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
                    var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { emailToken, email = user.Email });

                    // TODO : create a email service 
                    // Create an email and send it 
                    // assign token with email not confirmed 



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

                    Response.Cookies.Append(THDefaults.OneTimeMessage, "Welcome, " + welcomeName);
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

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    var customer = await _customerService.FindByEmailAsync(email);
                    if (customer != null)
                    {
                        // create jwt token 
                        var authClaims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, email),
                            new Claim(ClaimTypes.Email, email),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), 
                            new Claim(ClaimTypes.Role, customer.OnRole == THDefaults.DoctorUnverified ? THDefaults.Doctor : THDefaults.Patient)
                        };

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

                        var model = new ConfirmEmailModel
                        {
                            Email = email,
                            Message = "Email verification successfull."
                        };
                        return View(model);
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

        #endregion
    }

}
