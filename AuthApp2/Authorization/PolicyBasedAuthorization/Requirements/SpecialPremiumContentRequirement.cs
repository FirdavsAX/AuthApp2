using Microsoft.AspNetCore.Authorization;

namespace AuthApp2.Authorization.PolicyBasedAuthorization.Requirements;

public class SpecialPremiumContentRequirement : IAuthorizationRequirement
{
    public string Country { get; }
    public SpecialPremiumContentRequirement(string country)
    {
        Country = country;
    }
}
