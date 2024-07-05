using AuthApp2.Authentication;
using AuthApp2.Authorization.PolicyBasedAuthorization.ClaimTypes;
using AuthApp2.Authorization.RoleBasedAuthorization.Roles;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using System.Diagnostics.Metrics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthApp2.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController(UserManager<AppUser> userManager, IConfiguration configuration) : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await userManager.FindByNameAsync(model.UserName);
            if (user != null)
            {
                if (await userManager.CheckPasswordAsync(user, model.Password))
                {
                    var token = await GenerateTokenAsync(user, model.UserName);
                    return Ok(new { token });
                }
            }
            ModelState.AddModelError("", "Invalid login or username");
        }
        return BadRequest(ModelState);
    }
    [HttpPost("login-uzbeksitan")]
    public async Task<IActionResult> LoginUzbekistan([FromBody] LoginModel login)
    {
        //Again, this is a simplified implementation for demonstration purposes. In the real world, 
        //generally, there is only one login endpoint, and the country information is retrieved from the
        //database or other sources, such as IP addresses.
        if (ModelState.IsValid)
        {
            var user = await userManager.FindByNameAsync(login.UserName);
            if (user != null)
            {
                if(await userManager.CheckPasswordAsync(user, login.Password))
                {
                    var token = GenerateTokenAsync(login.UserName,"Russia");
                    return Ok(new { token });
                }
            }
            ModelState.AddModelError("", "Invalid username or password");
        }
        return BadRequest(ModelState);
    }
    [HttpPost("Register")]
    public async Task<IActionResult> Register([FromBody] AddOrUpdateUserModel model)
    {
        if (ModelState.IsValid)
        {
            var existeduser = await userManager.FindByNameAsync(model.UserName);
            if (existeduser != null)
            {
                ModelState.AddModelError("", "User already taken");
                return BadRequest(ModelState);
            }

            var user = new AppUser()
            {
                Email = model.Email,
                UserName = model.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await userManager.CreateAsync(user, model.Password);
            var roleResult = await userManager.AddToRoleAsync(user, AppRoles.VipUser);

            if (result.Succeeded && roleResult.Succeeded)
            {
                var token = await GenerateTokenAsync( model.UserName,"Uzbeksitan");
                return Ok(new { token });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
        }
        return BadRequest(ModelState);

    }
    private async Task<string?> GenerateTokenAsync(string userName, string country)
    {
        //Get secret key, audince , issuer in configuration
        var secret = configuration["JwtConfig:Secret"];
        var audience = configuration["JwtConfig:ValidAudiences"];
        var issuer = configuration["JwtConfig:ValidIssuer"];

        if (secret is null ||  audience is null || issuer is null)
        {
            throw new ApplicationException("Jwt is not set in the configuration");
        }

        //Encoding Secret Key
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var tokenHandler = new JwtSecurityTokenHandler();

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, userName),
                //In the real world, you can get the user’s subscription type and country from the database
                new Claim(AppClaimTypes.Subscription,"Premium"),
                new Claim(ClaimTypes.Country,country)
            }),
            Expires = DateTime.UtcNow.AddDays(1),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
        };


        var securityToken = tokenHandler.CreateToken(tokenDescriptor);
        var token = tokenHandler.WriteToken(securityToken);
        return token;
    }
}
