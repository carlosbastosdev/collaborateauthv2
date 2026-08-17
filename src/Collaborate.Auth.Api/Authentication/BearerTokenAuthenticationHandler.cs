using System.Security.Claims;
using System.Text.Encodings.Web;
using Collaborate.Auth.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Collaborate.Auth.Api.Authentication;

/// <summary>
/// A thin <see cref="AuthenticationHandler{TOptions}"/> that delegates every bit of token
/// parsing and signature verification to <see cref="ITokenValidator"/> (which in turn calls
/// Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler).
///
/// Why this exists instead of `AddJwtBearer(...)`: the repository this ships in was authored
/// in a sandbox with no NuGet registry access, and Microsoft.AspNetCore.Authentication.JwtBearer
/// isn't vendored anywhere available (see README.md "Offline build note"). In a normal
/// environment, this whole file — and the custom scheme registration in Program.cs — should
/// be deleted in favor of:
///
///     builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
///         .AddJwtBearer(options =>
///         {
///             options.Authority = "https://auth.collaborate.caseware.com";
///             options.Audience = Audiences.CollaborateAuth;
///         });
///
/// That's the correct, idiomatic choice and does everything this class does plus JWKS
/// discovery/rotation, which a same-process symmetric key doesn't need but a real deployment
/// does. This handler is a deliberate, documented substitute for one missing package — not a
/// argument that hand-rolling authentication is the better approach.
/// </summary>
public sealed class BearerTokenAuthenticationHandler : AuthenticationHandler<BearerTokenAuthenticationOptions>
{
    private readonly ITokenValidator _validator;

    public BearerTokenAuthenticationHandler(
        IOptionsMonitor<BearerTokenAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ITokenValidator validator)
        : base(options, logger, encoder)
    {
        _validator = validator;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            return AuthenticateResult.NoResult();
        }

        var raw = authHeader.ToString();
        if (!raw.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var token = raw["Bearer ".Length..].Trim();
        if (token.Length == 0)
        {
            return AuthenticateResult.Fail("Empty bearer token.");
        }

        var outcome = await _validator.ValidateAsync(token, Options.Audience);
        if (!outcome.IsValid || outcome.Token is null)
        {
            return AuthenticateResult.Fail(outcome.Error ?? "Token validation failed.");
        }

        var validated = outcome.Token;
        var claims = new List<Claim> { new("sub", validated.Subject) };
        claims.AddRange(validated.Scopes.Select(s => new Claim("scope", s)));
        if (validated.FirmId is not null) claims.Add(new Claim("firm_id", validated.FirmId));
        if (validated.UserType is not null) claims.Add(new Claim("user_type", validated.UserType));

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Bearer";
        return base.HandleChallengeAsync(properties);
    }
}
