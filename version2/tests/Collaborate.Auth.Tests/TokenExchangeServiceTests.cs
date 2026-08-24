using Collaborate.Auth.Core;
using Xunit;

namespace Collaborate.Auth.Tests;

/// <summary>
/// Mirrors, as individual [Fact]s, every guard TokenExchangeService's own doc comment
/// enumerates. If any of these ever goes red, one of the confused-deputy protections
/// described in docs/DESIGN.md has actually broken — that's the point of naming them this
/// explicitly instead of one big end-to-end test.
/// </summary>
public class TokenExchangeServiceTests
{
    private readonly TokenIssuer _issuer = new(TestKeys.Provider());
    private readonly TokenValidator _validator = new(TestKeys.Provider());
    private readonly TokenExchangeService _exchange;

    public TokenExchangeServiceTests()
    {
        _exchange = new TokenExchangeService(_validator, _issuer, InMemoryDelegationRegistry.Demo());
    }

    private string UserToken(string sub, params string[] scopes) => _issuer.Issue(new TokenIssueRequest(
        Subject: sub, Audience: Audiences.CollaborateApi, Scopes: scopes, Lifetime: TimeSpan.FromMinutes(5),
        FirmId: "firm-7", UserType: "external"));

    [Fact]
    public async Task RegisteredService_GetsATokenBack_WithScopeNarrowedToItsMaxGrant()
    {
        var subjectToken = UserToken("user-42", "comments.read", "comments.write");

        var outcome = await _exchange.ExchangeAsync(
            new TokenExchangeRequest(subjectToken, Audiences.CommentsApi, RequestedScope: null),
            callerServiceId: "notification-service");

        Assert.True(outcome.Success);
        // notification-service's max grant for comments-api is comments.read only —
        // comments.write is dropped even though the user themselves had it.
        Assert.Equal("comments.read", outcome.GrantedScope);
    }

    [Fact]
    public async Task ExchangedToken_CarriesTheOriginalUserAsSub_AndAnActClaimForTheService()
    {
        var subjectToken = UserToken("user-42", "comments.read");
        var outcome = await _exchange.ExchangeAsync(
            new TokenExchangeRequest(subjectToken, Audiences.CommentsApi, RequestedScope: null),
            callerServiceId: "notification-service");

        var exchanged = await _validator.ValidateAsync(outcome.AccessToken!, Audiences.CommentsApi);

        Assert.True(exchanged.IsValid);
        Assert.Equal("user-42", exchanged.Token?.Subject);
        Assert.Contains("notification-service", exchanged.Token?.ActorChainJson ?? "");
    }

    [Fact]
    public async Task ExchangedToken_CannotBeReplayedAgainstADifferentDownstreamApi()
    {
        var subjectToken = UserToken("user-42", "comments.read");
        var outcome = await _exchange.ExchangeAsync(
            new TokenExchangeRequest(subjectToken, Audiences.CommentsApi, RequestedScope: null),
            callerServiceId: "notification-service");

        var wrongAudience = await _validator.ValidateAsync(outcome.AccessToken!, Audiences.DocumentsApi);

        Assert.False(wrongAudience.IsValid);
    }

    [Fact]
    public async Task ServiceWithNoRegisteredGrantForTheAudience_IsDeniedOutright()
    {
        var subjectToken = UserToken("user-42", "comments.read");

        // No (notification-service, financial-api) grant exists in the demo registry.
        var outcome = await _exchange.ExchangeAsync(
            new TokenExchangeRequest(subjectToken, Audiences.FinancialApi, RequestedScope: null),
            callerServiceId: "notification-service");

        Assert.False(outcome.Success);
        Assert.Equal(TokenExchangeError.ServiceNotAuthorizedForAudience, outcome.Error);
    }

    [Fact]
    public async Task CannotMintAScopeTheSubjectNeverHad_EvenIfTheServiceIsRegisteredForTheAudience()
    {
        var subjectWithNoScopes = UserToken("user-99"); // no scopes at all

        var outcome = await _exchange.ExchangeAsync(
            new TokenExchangeRequest(subjectWithNoScopes, Audiences.CommentsApi, RequestedScope: "comments.read"),
            callerServiceId: "notification-service");

        Assert.False(outcome.Success);
        Assert.Equal(TokenExchangeError.NoScopeGrantedAfterNarrowing, outcome.Error);
    }

    [Fact]
    public async Task MalformedSubjectToken_IsRejectedAsInvalidGrant_NotACrash()
    {
        var outcome = await _exchange.ExchangeAsync(
            new TokenExchangeRequest("not-a-real-token", Audiences.CommentsApi, RequestedScope: null),
            callerServiceId: "notification-service");

        Assert.False(outcome.Success);
        Assert.Equal(TokenExchangeError.InvalidSubjectToken, outcome.Error);
    }

    [Fact]
    public async Task ActorChain_NestsAcrossTwoDelegationHops_InsteadOfBeingOverwritten()
    {
        var subjectToken = UserToken("user-42", "comments.read");
        var firstHop = await _exchange.ExchangeAsync(
            new TokenExchangeRequest(subjectToken, Audiences.CommentsApi, RequestedScope: null),
            callerServiceId: "notification-service");
        Assert.True(firstHop.Success);

        // The second hop needs a subject_token whose audience matches CollaborateApi to be
        // accepted by ExchangeAsync's validator call in this simplified slice, so we mint a
        // stand-in token carrying the same act claim the first hop produced, to demonstrate
        // chain-preservation in isolation from the audience/lifetime rules of a "real" token.
        var firstHopClaims = await _validator.ValidateAsync(firstHop.AccessToken!, Audiences.CommentsApi);
        var chainedSubjectToken = _issuer.Issue(new TokenIssueRequest(
            Subject: firstHopClaims.Token!.Subject,
            Audience: Audiences.CollaborateApi,
            Scopes: new[] { "comments.read" },
            Lifetime: TimeSpan.FromMinutes(5),
            ActorChainJson: firstHopClaims.Token.ActorChainJson));

        var secondHopRegistry = new InMemoryDelegationRegistry(new[]
        {
            new DelegationGrant("audit-relay-service", Audiences.CommentsApi, new HashSet<string> { "comments.read" }),
        });
        var secondHopExchange = new TokenExchangeService(_validator, _issuer, secondHopRegistry);

        var secondHop = await secondHopExchange.ExchangeAsync(
            new TokenExchangeRequest(chainedSubjectToken, Audiences.CommentsApi, RequestedScope: null),
            callerServiceId: "audit-relay-service");
        Assert.True(secondHop.Success);

        var secondHopValidated = await _validator.ValidateAsync(secondHop.AccessToken!, Audiences.CommentsApi);
        var actJson = secondHopValidated.Token?.ActorChainJson ?? "";

        Assert.Contains("audit-relay-service", actJson);
        Assert.Contains("notification-service", actJson);
    }
}
