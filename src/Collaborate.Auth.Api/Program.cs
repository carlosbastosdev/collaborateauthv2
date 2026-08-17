using Collaborate.Auth.Api.Authentication;
using Collaborate.Auth.Api.Endpoints;
using Collaborate.Auth.Core;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// --- Signing key -----------------------------------------------------------------------
// Dev-only symmetric key read from configuration (see appsettings.json / README for how to
// override it). Production note is on DevSymmetricSigningKeyProvider itself.
var signingKeyBase64 = builder.Configuration["Auth:SigningKey"]
    ?? throw new InvalidOperationException("Auth:SigningKey is not configured.");
var issuer = builder.Configuration["Auth:Issuer"] ?? "https://auth.collaborate.local";

builder.Services.AddSingleton<ISigningKeyProvider>(
    new DevSymmetricSigningKeyProvider(signingKeyBase64, issuer));

// --- Domain services ---------------------------------------------------------------------
builder.Services.AddSingleton<ITokenValidator, TokenValidator>();
builder.Services.AddSingleton<ITokenIssuer, TokenIssuer>();
builder.Services.AddSingleton<IDelegationRegistry>(InMemoryDelegationRegistry.Demo());
builder.Services.AddSingleton<TokenExchangeService>();

// --- AuthN/AuthZ ---------------------------------------------------------------------------
// See BearerTokenAuthenticationHandler's doc comment for why this is a custom scheme instead
// of AddJwtBearer(...) in this particular build environment.
builder.Services
    .AddAuthentication("Bearer")
    .AddScheme<BearerTokenAuthenticationOptions, BearerTokenAuthenticationHandler>(
        "Bearer", options => options.Audience = Audiences.CollaborateAuth);

builder.Services.AddSingleton<IAuthorizationHandler, ScopeAuthorizationHandler>();
builder.Services.AddAuthorization(options =>
{
    // Only internal services explicitly issued the "token-exchange" scope may call the
    // exchange endpoint at all — this is the first confused-deputy guard (see
    // TokenExchangeService's doc comment for the rest), enforced through the framework's
    // ordinary policy-based authorization rather than an ad hoc check inside the handler.
    options.AddPolicy(Policies.TokenExchange, policy =>
        policy.Requirements.Add(new ScopeRequirement("token-exchange")));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapTokenExchangeEndpoint();

app.Run();

// Exposed for WebApplicationFactory-style testing.
public partial class Program { }
