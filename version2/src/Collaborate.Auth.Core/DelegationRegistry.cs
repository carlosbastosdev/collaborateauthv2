namespace Collaborate.Auth.Core;

public interface IDelegationRegistry
{
    /// <summary>
    /// Looks up the maximum an internal service is trusted to request when exchanging a
    /// user's token for one scoped to <paramref name="audience"/>. Returns false if the
    /// service has no registered relationship with that audience at all — the request is
    /// rejected outright rather than falling back to some default, because an unregistered
    /// (service, audience) pair is exactly the "an internal service reaches somewhere it was
    /// never meant to" shape a confused-deputy bug looks like.
    /// </summary>
    bool TryGetGrant(string serviceId, string audience, out DelegationGrant grant);
}

/// <summary>
/// Stand-in for what would, in production, be a table Collaborate's platform team edits
/// through a review process — "notification-service may act for users against comments-api
/// and documents-api, but never financial-api." Wiring this to a real store (and gating
/// changes to it) is out of scope for this slice; the interface is what matters.
/// </summary>
public sealed class InMemoryDelegationRegistry : IDelegationRegistry
{
    private readonly Dictionary<(string ServiceId, string Audience), DelegationGrant> _grants;

    public InMemoryDelegationRegistry(IEnumerable<DelegationGrant> seed)
    {
        _grants = seed.ToDictionary(g => (g.ServiceId, g.Audience));
    }

    public static InMemoryDelegationRegistry Demo() => new(new[]
    {
        new DelegationGrant(
            ServiceId: "notification-service",
            Audience: Audiences.CommentsApi,
            MaxScopes: new HashSet<string> { "comments.read" }),
        new DelegationGrant(
            ServiceId: "notification-service",
            Audience: Audiences.DocumentsApi,
            MaxScopes: new HashSet<string> { "documents.read" }),
        // Deliberately no grant for notification-service -> financial-api: that service has
        // no legitimate reason to reach financial data on a user's behalf, so it can't.
    });

    public bool TryGetGrant(string serviceId, string audience, out DelegationGrant grant)
    {
        var found = _grants.TryGetValue((serviceId, audience), out var g);
        grant = g!;
        return found;
    }
}

public static class Audiences
{
    /// <summary>Audience for CIAS's own token-exchange endpoint (caller/service tokens).</summary>
    public const string CollaborateAuth = "collaborate-auth";

    /// <summary>Default audience for ordinary user access tokens issued at login.</summary>
    public const string CollaborateApi = "collaborate-api";

    public const string CommentsApi = "comments-api";
    public const string DocumentsApi = "documents-api";
    public const string FinancialApi = "financial-api";
}
