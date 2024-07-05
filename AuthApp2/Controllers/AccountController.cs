﻿using AuthApp2.Authentication;
using AuthApp2.Roles;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthApp2.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController(UserManager<AppUser> userManager, IConfiguration configuration,SignInManager<AppUser> signingManager) : ControllerBase
{
    private readonly SignInManager<AppUser> _signInManager = signingManager ?? throw new ArgumentNullException(nameof(configuration));
    private readonly IConfiguration _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    private readonly UserManager<AppUser> _userManager = userManager ?? throw new ArgumentNullException(nameof(configuration));
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user != null)
            {
                var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password,lockoutOnFailure : true);

                if (result.Succeeded)
                {
                    var token = await GenerateToken(user, model.UserName);
                    return Ok(new { token });
                }
            }
            ModelState.AddModelError("", "Invalid login or username");
        }
        return BadRequest(ModelState);
    }
    [HttpPost("Register")]
    public async Task<IActionResult> Register([FromBody] AddOrUpdateUserModel model)
    {
        if (ModelState.IsValid)
        {
            var existeduser = await _userManager.FindByNameAsync(model.UserName);
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

            var result = await _userManager.CreateAsync(user, model.Password);
            var roleResult = await _userManager.AddToRoleAsync(user, AppRoles.VipUser);

            if (result.Succeeded && roleResult.Succeeded)
            {
                var token = await GenerateToken(user,model.UserName);
                return Ok(new { token });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
        }
        return BadRequest(ModelState);

    }
    private async Task<string?> GenerateToken(AppUser user,string userName)
    {
        var secret = configuration["JwtConfig:Secret"];
        var audience = configuration["JwtConfig:ValidAudiences"];
        var issuer = configuration["JwtConfig:ValidIssuer"];
        if (secret is null ||  audience is null || issuer is null)
        {
            throw new ApplicationException("Jwt is not set in the configuration");
        }
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var tokenHandler = new JwtSecurityTokenHandler();

        var userRoles = await _userManager.GetRolesAsync(user);
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name,userName)
        };
        claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(1),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature)
        };
        var securityToken = tokenHandler.CreateToken(tokenDescriptor);
        var token = tokenHandler.WriteToken(securityToken);
        return token;
    }
}
