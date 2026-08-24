using System.Text.Json;

namespace Collaborate.Auth.Core;

/// <summary>
/// Implements the on-behalf-of slice: an internal service presents a user's access token
/// (subject_token) and gets back a new token, narrower in every dimension, scoped to one
/// downstream API. This is a simplified OAuth 2.0 Token Exchange (RFC 8693) — simplified
/// because we don't need the full grant-type/token-type negotiation machinery RFC 8693
/// defines for a single internal use case, but the shape (subject_token in, narrower
/// access_token out, actor claim preserved) is the same.
///
/// Confused-deputy guards, all enforced here rather than trusted to the caller:
///   1. The calling service must be pre-registered to act for the requested audience at all
///      (<see cref="IDelegationRegistry"/>) — an unregistered service gets nothing.
///   2. Granted scope is the *intersection* of what was requested, what the subject actually
///      has, and what the service is registered for — it can only ever narrow, never widen.
///   3. The issued token's audience is the single requested downstream API — it cannot be
///      replayed against any other resource API.
///   4. Authorization at the resource API is always against `sub` (the original user), never
///      against the calling service's own identity — see README for why that's the part that
///      actually prevents "confused deputy," not just the audience/scope restriction.
///   5. The `act` claim is preserved and extended, never dropped, so a chain of delegation
///      hops stays attributable to a human end-user for audit purposes.
///   6. The issued token is short-lived — seconds, not minutes — since it only needs to
///      survive one downstream call, not a session.
/// </summary>
public sealed class TokenExchangeService
{
    private static readonly TimeSpan DelegatedTokenLifetime = TimeSpan.FromSeconds(60);

    private readonly ITokenValidator _validator;
    private readonly ITokenIssuer _issuer;
    private readonly IDelegationRegistry _registry;

    public TokenExchangeService(ITokenValidator validator, ITokenIssuer issuer, IDelegationRegistry registry)
    {
        _validator = validator;
        _issuer = issuer;
        _registry = registry;
    }

    public async Task<TokenExchangeOutcome> ExchangeAsync(
        TokenExchangeRequest request,
        string callerServiceId,
        CancellationToken ct = default)
    {
        var validation = await _validator.ValidateAsync(request.SubjectToken, Audiences.CollaborateApi, ct);
        if (!validation.IsValid || validation.Token is null)
        {
            return TokenExchangeOutcome.Fail(
                TokenExchangeError.InvalidSubjectToken,
                validation.Error ?? "subject_token is not a valid Collaborate access token.");
        }

        var subject = validation.Token;

        if (!_registry.TryGetGrant(callerServiceId, request.Audience, out var grant))
        {
            return TokenExchangeOutcome.Fail(
                TokenExchangeError.ServiceNotAuthorizedForAudience,
                $"'{callerServiceId}' is not registered to act on behalf of users against '{request.Audience}'.");
        }

        var requested = request.RequestedScope is null
            ? subject.Scopes
            : request.RequestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);

        var grantedScope = ScopeNarrowing.Intersect(requested, subject.Scopes, grant.MaxScopes);

        if (grantedScope.Count == 0)
        {
            return TokenExchangeOutcome.Fail(
                TokenExchangeError.NoScopeGrantedAfterNarrowing,
                "No scope survives the intersection of requested, subject, and service-grant scopes.");
        }

        var actorClaim = BuildActorChain(callerServiceId, subject.ActorChainJson);

        var accessToken = _issuer.Issue(new TokenIssueRequest(
            Subject: subject.Subject,
            Audience: request.Audience,
            Scopes: grantedScope,
            Lifetime: DelegatedTokenLifetime,
            FirmId: subject.FirmId,
            UserType: subject.UserType,
            Azp: subject.Azp,
            ActorChainJson: actorClaim));

        return TokenExchangeOutcome.Ok(accessToken, (int)DelegatedTokenLifetime.TotalSeconds, string.Join(' ', grantedScope));
    }

    /// <summary>
    /// RFC 8693 §4.1: act claim nests, it doesn't overwrite. If the subject token already
    /// carries an actor (e.g. this is the second hop of a delegation chain), the new actor
    /// wraps around it so the full chain back to a real, attributable actor is preserved.
    /// </summary>
    private static string BuildActorChain(string callerServiceId, string? existingActClaimJson)
    {
        var actor = new Dictionary<string, object> { ["sub"] = callerServiceId };

        if (existingActClaimJson is not null)
        {
            actor["act"] = JsonSerializer.Deserialize<object>(existingActClaimJson)!;
        }

        return JsonSerializer.Serialize(actor);
    }
}

public static class ScopeNarrowing
{
    /// <summary>
    /// Pure function, deliberately: this is the one rule that decides how much access a
    /// delegated token ends up with, so it needs to be trivially unit-testable without any
    /// JWT machinery in the way. Order of arguments doesn't matter — it's a plain set
    /// intersection — but the name of each parameter documents where each constraint comes
    /// from.
    /// </summary>
    public static IReadOnlySet<string> Intersect(
        IEnumerable<string> requested,
        IEnumerable<string> subjectScopes,
        IEnumerable<string> serviceMaxScopes)
    {
        var result = new HashSet<string>(requested, StringComparer.Ordinal);
        result.IntersectWith(subjectScopes);
        result.IntersectWith(serviceMaxScopes);
        return result;
    }
}
