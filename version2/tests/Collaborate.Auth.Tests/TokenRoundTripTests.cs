using Collaborate.Auth.Core;
using Xunit;

namespace Collaborate.Auth.Tests;

public class TokenRoundTripTests
{
    private readonly TokenIssuer _issuer = new(TestKeys.Provider());
    private readonly TokenValidator _validator = new(TestKeys.Provider());

    [Fact]
    public async Task RoundTrippedToken_ValidatesSuccessfully()
    {
        var token = IssueUserToken();
        var outcome = await _validator.ValidateAsync(token, Audiences.CollaborateApi);

        Assert.True(outcome.IsValid);
    }

    [Fact]
    public async Task RoundTrippedToken_PreservesSubjectFirmAndScopes()
    {
        var token = IssueUserToken();
        var outcome = await _validator.ValidateAsync(token, Audiences.CollaborateApi);

        Assert.Equal("user-42", outcome.Token?.Subject);
        Assert.Equal("firm-7", outcome.Token?.FirmId);
        Assert.True(outcome.Token?.Scopes.SetEquals(new[] { "comments.read", "documents.read" }));
    }

    [Fact]
    public async Task TokenIssuedForOneAudience_IsRejectedForADifferentOne()
    {
        var token = IssueUserToken();
        var outcome = await _validator.ValidateAsync(token, "some-other-api");

        Assert.False(outcome.IsValid);
    }

    [Fact]
    public async Task ExpiredToken_IsRejected()
    {
        var expired = _issuer.Issue(new TokenIssueRequest(
            Subject: "user-42",
            Audience: Audiences.CollaborateApi,
            Scopes: new[] { "comments.read" },
            Lifetime: TimeSpan.FromSeconds(-1)));

        var outcome = await _validator.ValidateAsync(expired, Audiences.CollaborateApi);

        Assert.False(outcome.IsValid);
    }

    [Fact]
    public async Task GarbageInput_IsRejectedNotThrown()
    {
        var outcome = await _validator.ValidateAsync("not-a-jwt", Audiences.CollaborateApi);

        Assert.False(outcome.IsValid);
    }

    private string IssueUserToken() => _issuer.Issue(new TokenIssueRequest(
        Subject: "user-42",
        Audience: Audiences.CollaborateApi,
        Scopes: new[] { "comments.read", "documents.read" },
        Lifetime: TimeSpan.FromMinutes(5),
        FirmId: "firm-7",
        UserType: "external"));
}
