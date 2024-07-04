using AuthApp2.Authentication;
using AuthApp2.Authorization.ClaimBasedAuthorization.AuthorizationPolicies;
using AuthApp2.Authorization.ClaimBasedAuthorization.ClaimTypes;
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

        [Authorize(Policy = AppAuthorizationPolicies.RequireDrivingLicenseNumber)]
        [Authorize(Policy = AppAuthorizationPolicies.RequireAccessNumber)]  
        [HttpGet("driving-license-and-access-number")]
        public ActionResult GetCountryAndAccessNumber()
        {
            var drivingLicenseNumber = User.Claims.FirstOrDefault(c => c.Type == AppClaimTypes.DrivingLicenseNumber)?.Value;
            var accessNumber = User.Claims.FirstOrDefault(c => c.Type == AppClaimTypes.AccessNumber)?.Value;

            return Ok(new { drivingLicenseNumber, accessNumber });
        }

        /// <summary>
        /// get country with requireCountry policy in authorize attribute
        /// </summary>
        /// <returns></returns>
        [Authorize(Policy = AppAuthorizationPolicies.RequireCountry)]
        [HttpGet("country")]
        public ActionResult GetCountry()
        {
            var country = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Country)?.Value;
            return Ok(country);
        }
        
        [Authorize(Policy = AppAuthorizationPolicies.RequireDrivingLicenseNumber)]
        [HttpGet("driving-license")]
        public ActionResult GetDrivingLicense()
        {
            var drivingLicenseNumber = User.Claims.FirstOrDefault(c => c.Type == AppClaimTypes.DrivingLicenseNumber)?.Value ;
            return Ok(drivingLicenseNumber);
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
