using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Tracendbk.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("signin-google")]
        public IActionResult SignInWithGoogle()
        {
            var redirectUrl = Url.Action("GoogleResponse", "Auth", null, Request.Scheme);
            var state = Guid.NewGuid().ToString(); // Generate a unique state value
            HttpContext.Session.SetString("oauth_state", state); // Store state in session
            var properties = new AuthenticationProperties
            {
                RedirectUri = redirectUrl,
                Items = { { "state", state } } // Set the state in the properties
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var info = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
            if (info?.Succeeded ?? false)
            {
                var expectedState = HttpContext.Session.GetString("oauth_state"); // Retrieve the expected state
                var receivedState = info.Properties.Items["state"]; // Get the state from the callback properties

                // Validate state
                if (expectedState != receivedState)
                {
                    return BadRequest("Invalid state");
                }

                // Logging and JWT token generation logic
                Console.WriteLine("OAuth info: " + info.Principal.Identity.Name);
                var claims = info.Principal.Claims.ToList();
                var emailClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
                var jwtToken = GenerateJwtToken(emailClaim);
                return Ok(new { Token = jwtToken });
            }

            return Unauthorized();
        }


        private string GenerateJwtToken(string email)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Email, email) }),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
