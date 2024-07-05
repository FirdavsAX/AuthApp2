using AuthApp2.Authentication;
using AuthApp2.Authorization.PolicyBasedAuthorization.AuthorizationPolicies;
using AuthApp2.Authorization.PolicyBasedAuthorization.ClaimTypes;
using AuthApp2.Authorization.RoleBasedAuthorization.Roles;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
namespace AuthApp2.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [Authorize(Policy = AppAuthorizationPolicies.SpecialPremiumContent)]
        [HttpGet("get-premium",Name = " GetPRemiumWeatherForecast")]
        public IEnumerable<WeatherForecast> GetPremium()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
           .ToArray();
        }
        
        [HttpGet(Name = "GetWeatherForecast")]
        [Authorize(Roles = $"{AppRoles.User},{AppRoles.VipUser},{AppRoles.Administrator}")]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
        
        [HttpGet("vip",Name = "GetVipWeatherForecast")]
        [Authorize(Roles = AppRoles.VipUser)]
        [Authorize(Roles = AppRoles.User)]
        public IEnumerable<WeatherForecast> GetVip()
        {
            return Enumerable.Range(1,5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20,55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)],
            }).ToArray();
        }
        
        [HttpGet("admin-with-policy",Name ="GetAdminWeatherForecastWithPolicy")]
        [Authorize(Policy = "RequireAdminstatorRole")]
        public IEnumerable<WeatherForecast> GetAdminWithPolicy()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)],
            }).ToArray();
        }
    }
}
