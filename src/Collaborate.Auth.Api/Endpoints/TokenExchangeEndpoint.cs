using System.Security.Claims;
using Collaborate.Auth.Api.Contracts;
using Collaborate.Auth.Core;

namespace Collaborate.Auth.Api.Endpoints;

public static class TokenExchangeEndpoint
{
    public static IEndpointRouteBuilder MapTokenExchangeEndpoint(this IEndpointRouteBuilder app)
    {
        app.MapPost("/api/token-exchange", HandleAsync)
            .RequireAuthorization(Policies.TokenExchange)
            .WithName("TokenExchange");

        return app;
    }

    private static async Task<IResult> HandleAsync(
        TokenExchangeHttpRequest body,
        ClaimsPrincipal caller,
        TokenExchangeService service,
        CancellationToken ct)
    {
        if (body.GrantType != TokenExchangeConstants.GrantType)
        {
            return Results.BadRequest(new TokenExchangeHttpError(
                "unsupported_grant_type",
                $"grant_type must be '{TokenExchangeConstants.GrantType}'."));
        }

        if (string.IsNullOrWhiteSpace(body.SubjectToken) || string.IsNullOrWhiteSpace(body.Audience))
        {
            return Results.BadRequest(new TokenExchangeHttpError(
                "invalid_request", "subject_token and audience are required."));
        }

        // The caller authenticated as itself via the Bearer scheme (see
        // BearerTokenAuthenticationHandler) — its own token's `sub` is the internal service
        // identity we check delegation grants against. We never trust a service-identity
        // string supplied in the request body; it can only be the thing the caller's own
        // validated token says it is.
        var callerServiceId = caller.FindFirstValue("sub");
        if (callerServiceId is null)
        {
            return Results.Problem("Authenticated principal has no subject.", statusCode: 500);
        }

        var outcome = await service.ExchangeAsync(
            new TokenExchangeRequest(body.SubjectToken, body.Audience, body.Scope),
            callerServiceId,
            ct);

        if (!outcome.Success)
        {
            return outcome.Error switch
            {
                TokenExchangeError.ServiceNotAuthorizedForAudience => Results.Json(
                    new TokenExchangeHttpError("access_denied", outcome.ErrorDescription!),
                    statusCode: StatusCodes.Status403Forbidden),
                TokenExchangeError.InvalidSubjectToken => Results.BadRequest(
                    new TokenExchangeHttpError("invalid_grant", outcome.ErrorDescription!)),
                TokenExchangeError.NoScopeGrantedAfterNarrowing => Results.BadRequest(
                    new TokenExchangeHttpError("invalid_scope", outcome.ErrorDescription!)),
                _ => Results.BadRequest(new TokenExchangeHttpError("invalid_request", outcome.ErrorDescription ?? "Request could not be processed.")),
            };
        }

        return Results.Ok(new TokenExchangeHttpResponse(
            AccessToken: outcome.AccessToken!,
            IssuedTokenType: TokenExchangeConstants.AccessTokenType,
            TokenType: "Bearer",
            ExpiresIn: outcome.ExpiresInSeconds!.Value,
            Scope: outcome.GrantedScope!));
    }
}

public static class Policies
{
    public const string TokenExchange = "TokenExchange";
}
