using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TH.Configurations;
using TH.Models;
using JwtRegisteredClaimNames = System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames;

namespace TH.Controllers
{
    public class AuthController : Controller
    {
        #region Fields
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly JwtConfig _jwtConfig;

        #endregion

        #region Ctor
        public AuthController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IOptionsMonitor<JwtConfig> optionMonitor)
        {
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
            var user = await _userManager.FindByEmailAsync(model.Email);
            if(user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, model.Email),
                    new Claim(ClaimTypes.Email, model.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                var userRoles = await _userManager.GetRolesAsync(user);
                foreach(var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var jwtToken = GetToken(authClaims);
                var token = new JwtSecurityTokenHandler().WriteToken(jwtToken);

                // generate refresh token 

                // add cookies (jwt + refresh)

            }

            return RedirectToAction("Index", "Home");
        }

        public IActionResult Logout()
        {
            // TODO : clear the cookies 

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
                return View(model);
            }

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
            if (roleExist && role != "Admin")
            {
                var result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                {
                    var errorMessages = string.Join("<br />", result.Errors.Select(e => e.Description));
                    ViewData["Error"] = errorMessages;
                    return View(model);
                }
                await _userManager.AddToRoleAsync(user, role);

                // Add token to verify the email 
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new {token, email = user.Email});

                // TODO : create a email service 
                // Create an email and send it 
                // assign token with email not confirmed 

                // create a token as RegisteredUnvarified
                // set cookies 

                return RedirectToAction("Index","Home");
            } 
            else
            {
                ViewData["Error"] = "The role is not valid.";
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
                if(result.Succeeded)
                {
                    // TODO : create token with registered role 
                    // assign the cookie
                }
            }
            return View();
        }

        #endregion
    }

}
