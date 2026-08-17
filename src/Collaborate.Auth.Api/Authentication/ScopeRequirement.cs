using Microsoft.AspNetCore.Authorization;

namespace Collaborate.Auth.Api.Authentication;

/// <summary>
/// Standard ASP.NET Core authorization extensibility (<see cref="IAuthorizationRequirement"/> +
/// <see cref="AuthorizationHandler{TRequirement}"/>) — this is the framework's designed
/// extension point for exactly this kind of check, not a workaround.
/// </summary>
public sealed class ScopeRequirement : IAuthorizationRequirement
{
    public ScopeRequirement(string scope) => Scope = scope;
    public string Scope { get; }
}

public sealed class ScopeAuthorizationHandler : AuthorizationHandler<ScopeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, ScopeRequirement requirement)
    {
        if (context.User.Claims.Any(c => c.Type == "scope" && c.Value == requirement.Scope))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
