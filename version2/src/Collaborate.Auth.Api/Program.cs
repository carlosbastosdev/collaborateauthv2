using Collaborate.Auth.Api.Authentication;
using Collaborate.Auth.Api.Endpoints;
using Collaborate.Auth.Core;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// --- Signing key -----------------------------------------------------------------------
// Dev-only symmetric key read from configuration (see appsettings.json / README for how to
// override it). Production note is on DevSymmetricSigningKeyProvider itself.
var signingKeyBase64 = builder.Configuration["Auth:SigningKey"]
    ?? throw new InvalidOperationException("Auth:SigningKey is not configured.");
var issuer = builder.Configuration["Auth:Issuer"] ?? "https://auth.collaborate.local";

var signingKeyProvider = new DevSymmetricSigningKeyProvider(signingKeyBase64, issuer);
builder.Services.AddSingleton<ISigningKeyProvider>(signingKeyProvider);

// --- Domain services ---------------------------------------------------------------------
builder.Services.AddSingleton<ITokenValidator, TokenValidator>();
builder.Services.AddSingleton<ITokenIssuer, TokenIssuer>();
builder.Services.AddSingleton<IDelegationRegistry>(InMemoryDelegationRegistry.Demo());
builder.Services.AddSingleton<TokenExchangeService>();

// --- AuthN/AuthZ ---------------------------------------------------------------------------
// v2: the idiomatic call — JwtBearer owns token parsing, signature verification, and
// expiry/audience/issuer checks entirely. Nothing in this project touches a raw token
// string for this path. This scheme validates the CALLER's own token (the internal service
// hitting /api/token-exchange); the user's subject_token inside the request *body* is a
// separate, manual validation via ITokenValidator (see TokenExchangeService) because it
// never arrives in the Authorization header, so JwtBearer's pipeline never sees it — that
// part is unavoidably "custom", but it's still 100% JsonWebTokenHandler underneath, never
// hand-rolled parsing.
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = signingKeyProvider.Issuer,
            ValidateIssuer = true,
            ValidAudience = Audiences.CollaborateAuth,
            ValidateAudience = true,
            IssuerSigningKey = signingKeyProvider.GetValidationKey(),
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        // Without this, JwtBearer remaps short claim names ("sub", "scope", ...) to long
        // legacy XML-namespace claim types for backward compatibility with the old
        // JwtSecurityTokenHandler pipeline — which would silently break both
        // ScopeAuthorizationHandler (looks for a claim literally typed "scope") and
        // TokenExchangeEndpoint (looks up "sub" via FindFirstValue). Keep claim types exactly
        // as they appear in the token.
        options.MapInboundClaims = false;
    });

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
