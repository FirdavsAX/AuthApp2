using AuthApp2.Authentication;
using AuthApp2.Authorization.ClaimBasedAuthorization.AuthorizationPolicies;
using AuthApp2.Authorization.ClaimBasedAuthorization.ClaimTypes;
using AuthApp2.Authorization.RoleBasedAuthorization.Roles;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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

        public IEnumerable<WeatherForecast> GetFree()
        {
            var a = User;
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
        [Authorize(Policy = AppAuthorizationPolicies.RequireDrivingLicenseNumber)]
        [HttpGet("driving-license")]
        public ActionResult GetDrivingLicense()
        {
            var drivingLicenseNumber = User.Claims.FirstOrDefault(c => c.Type == AppClaimTypes.DrivingLicenseNumber)?.Value ;
            return Ok();
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
