﻿using Microsoft.AspNetCore.Authorization;

namespace AuthApp2.Authorization.PolicyBasedAuthorization;

public class SpecialPremiumContentRequirement : IAuthorizationRequirement
{
    public string Country { get; }
    public SpecialPremiumContentRequirement(string country)
    {
        Country = country;  
    }
}
