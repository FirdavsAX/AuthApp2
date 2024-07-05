using AuthApp2.Authorization.PolicyBasedAuthorization.Requirements;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AuthApp2.Authorization.PolicyBasedAuthorization;

public class SpecialPremiumContentAuthorizationHandler : AuthorizationHandler<SpecialPremiumContentRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, SpecialPremiumContentRequirement requirement)
    {
        var hasPremiumSubscriptionClaim = context.User.HasClaim(claim => claim.Type == "Subscription" &&  claim.Value == "Premium");

        if(!hasPremiumSubscriptionClaim)
        {
            return Task.CompletedTask;
        }
        
        var countryClaim = context.User.FindFirst(claim => claim.Type == System.Security.Claims.ClaimTypes.Country);
        
        if (countryClaim == null || string.IsNullOrWhiteSpace(countryClaim.ToString())) 
        {
            return Task.CompletedTask;
        }

        if(countryClaim.Value == requirement.Country)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
