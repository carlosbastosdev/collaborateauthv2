namespace Collaborate.Auth.Core;

/// <summary>
/// A validated set of claims lifted out of an inbound access token. This is the shape the
/// rest of the domain works with — nothing downstream touches raw JWT strings or does its
/// own signature verification.
/// </summary>
public sealed record ValidatedToken(
    string Subject,
    string? FirmId,
    string? UserType,
    string? Azp,
    IReadOnlySet<string> Scopes,
    string? ActorChainJson,
    DateTimeOffset ExpiresAt);

public sealed record TokenValidationOutcome(bool IsValid, ValidatedToken? Token, string? Error)
{
    public static TokenValidationOutcome Success(ValidatedToken token) => new(true, token, null);
    public static TokenValidationOutcome Failure(string error) => new(false, null, error);
}

/// <summary>
/// A single "may-act-for" grant: the maximum an internal service is trusted to request when
/// exchanging a user's token for a narrower one scoped to <see cref="Audience"/>. This is the
/// pre-registered relationship that prevents an internal service from minting itself broader
/// access than it has ever been explicitly trusted with — the core confused-deputy guard.
/// </summary>
public sealed record DelegationGrant(string ServiceId, string Audience, IReadOnlySet<string> MaxScopes);

public sealed record TokenExchangeRequest(
    string SubjectToken,
    string Audience,
    string? RequestedScope);

public enum TokenExchangeError
{
    InvalidSubjectToken,
    ServiceNotAuthorizedForAudience,
    NoScopeGrantedAfterNarrowing,
}

public sealed record TokenExchangeOutcome(
    bool Success,
    string? AccessToken,
    int? ExpiresInSeconds,
    string? GrantedScope,
    TokenExchangeError? Error,
    string? ErrorDescription)
{
    public static TokenExchangeOutcome Ok(string accessToken, int expiresIn, string grantedScope) =>
        new(true, accessToken, expiresIn, grantedScope, null, null);

    public static TokenExchangeOutcome Fail(TokenExchangeError error, string description) =>
        new(false, null, null, null, error, description);
}

/// <summary>
/// Everything needed to mint a token. Kept generic on purpose: the same primitive issues both
/// a "seed" user token (standing in for what CIAS would issue at login) and the narrower
/// delegated token produced by token exchange — there's exactly one place JWTs get created.
/// </summary>
public sealed record TokenIssueRequest(
    string Subject,
    string Audience,
    IEnumerable<string> Scopes,
    TimeSpan Lifetime,
    string? FirmId = null,
    string? UserType = null,
    string? Azp = null,
    string? ActorChainJson = null);
