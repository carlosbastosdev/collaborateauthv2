// This is a plain executable, not an xunit project — see README.md "Offline build note".
// Microsoft.NET.Test.Sdk / xunit / xunit.runner.visualstudio are all ordinary NuGet packages
// and none of them happened to be vendored anywhere on the sandbox this repo was authored in
// (unlike the five Microsoft.IdentityModel assemblies, which ship inside the .NET SDK's own
// `dotnet-user-jwts` tool and could be copied out — see /lib). Rather than fake test coverage
// with a framework that can't actually run here, this project exercises the same
// Collaborate.Auth.Core types a normal xunit suite would, via a small assertion helper, so
// `dotnet run` is a real, offline, zero-dependency proof the logic works. Every [Check] below
// reads like an xunit [Fact] on purpose — porting to xunit once the registry is reachable is
// a mechanical find/replace, not a rewrite.
using Collaborate.Auth.Core;

var failures = new List<string>();
var passed = 0;

void Check(string name, bool condition)
{
    if (condition)
    {
        passed++;
        Console.WriteLine($"  PASS  {name}");
    }
    else
    {
        failures.Add(name);
        Console.WriteLine($"  FAIL  {name}");
    }
}

// A couple of "mint a demo token for manual curl testing" utility commands live behind
// argv so this file can do double duty without a second entry point.
if (args.Length > 0 && args[0] is "mint-user" or "mint-service")
{
    RunMintCommand(args[0]);
    return;
}

Console.WriteLine("Collaborate.Auth.Core — verification run (no external test framework; see file header)\n");

const string SigningKeyBase64 = "N2Y5YzFlZDctNTFmMS00MTgxLWEwZjItYzQwYjE1NGJjZjNi";
const string Issuer = "https://auth.collaborate.local";

ISigningKeyProvider Keys() => new DevSymmetricSigningKeyProvider(SigningKeyBase64, Issuer);

// ---------------------------------------------------------------------------------------
Console.WriteLine("ScopeNarrowing.Intersect (pure logic)");
{
    var result = ScopeNarrowing.Intersect(
        requested: new[] { "comments.read", "comments.write", "documents.read" },
        subjectScopes: new[] { "comments.read", "comments.write" },
        serviceMaxScopes: new[] { "comments.read" });

    Check("narrows to the intersection of all three sets", result.SetEquals(new[] { "comments.read" }));

    var empty = ScopeNarrowing.Intersect(
        requested: new[] { "financial.read" },
        subjectScopes: new[] { "comments.read" },
        serviceMaxScopes: new[] { "financial.read" });

    Check("returns empty when subject never had the scope at all", empty.Count == 0);
}

// ---------------------------------------------------------------------------------------
Console.WriteLine("\nTokenIssuer + TokenValidator round trip");
{
    var issuer = new TokenIssuer(Keys());
    var validator = new TokenValidator(Keys());

    var token = issuer.Issue(new TokenIssueRequest(
        Subject: "user-42",
        Audience: Audiences.CollaborateApi,
        Scopes: new[] { "comments.read", "documents.read" },
        Lifetime: TimeSpan.FromMinutes(5),
        FirmId: "firm-7",
        UserType: "external"));

    var outcome = await validator.ValidateAsync(token, Audiences.CollaborateApi);

    Check("round-tripped token validates successfully", outcome.IsValid);
    Check("subject claim survives the round trip", outcome.Token?.Subject == "user-42");
    Check("firm_id claim survives the round trip", outcome.Token?.FirmId == "firm-7");
    Check("scopes survive the round trip", outcome.Token?.Scopes.SetEquals(new[] { "comments.read", "documents.read" }) == true);

    var wrongAudience = await validator.ValidateAsync(token, "some-other-api");
    Check("token issued for one audience is rejected for a different one", !wrongAudience.IsValid);

    var expired = new TokenIssuer(Keys()).Issue(new TokenIssueRequest(
        Subject: "user-42", Audience: Audiences.CollaborateApi, Scopes: new[] { "comments.read" },
        Lifetime: TimeSpan.FromSeconds(-1)));
    var expiredOutcome = await validator.ValidateAsync(expired, Audiences.CollaborateApi);
    Check("expired token is rejected", !expiredOutcome.IsValid);

    Check("garbage input is rejected, not thrown", !(await validator.ValidateAsync("not-a-jwt", Audiences.CollaborateApi)).IsValid);
}

// ---------------------------------------------------------------------------------------
Console.WriteLine("\nTokenExchangeService — on-behalf-of / confused-deputy guards");
{
    var issuer = new TokenIssuer(Keys());
    var validator = new TokenValidator(Keys());
    var registry = InMemoryDelegationRegistry.Demo();
    var exchange = new TokenExchangeService(validator, issuer, registry);

    string UserToken(string sub, params string[] scopes) => issuer.Issue(new TokenIssueRequest(
        Subject: sub, Audience: Audiences.CollaborateApi, Scopes: scopes, Lifetime: TimeSpan.FromMinutes(5),
        FirmId: "firm-7", UserType: "external"));

    // Happy path: notification-service is registered to act for users against comments-api.
    var subjectToken = UserToken("user-42", "comments.read", "comments.write");
    var happy = await exchange.ExchangeAsync(
        new TokenExchangeRequest(subjectToken, Audiences.CommentsApi, RequestedScope: null),
        callerServiceId: "notification-service");

    Check("registered service gets a token back", happy.Success);
    Check("granted scope is narrowed to the service's max grant (write is dropped)", happy.GrantedScope == "comments.read");

    if (happy.Success)
    {
        var exchanged = await validator.ValidateAsync(happy.AccessToken!, Audiences.CommentsApi);
        Check("exchanged token validates against the narrow audience it was minted for", exchanged.IsValid);
        Check("exchanged token still carries the ORIGINAL USER as sub, not the service", exchanged.Token?.Subject == "user-42");
        Check("exchanged token carries an act claim naming the calling service", exchanged.Token?.ActorChainJson?.Contains("notification-service") == true);

        var wrongAudience = await validator.ValidateAsync(happy.AccessToken!, Audiences.DocumentsApi);
        Check("exchanged token CANNOT be replayed against a different downstream API", !wrongAudience.IsValid);
    }

    // Confused-deputy guard: no grant exists for (notification-service, financial-api).
    var deniedAudience = await exchange.ExchangeAsync(
        new TokenExchangeRequest(subjectToken, Audiences.FinancialApi, RequestedScope: null),
        callerServiceId: "notification-service");
    Check("service with no registered grant for the audience is denied outright", !deniedAudience.Success);
    Check("denial reason is ServiceNotAuthorizedForAudience", deniedAudience.Error == TokenExchangeError.ServiceNotAuthorizedForAudience);

    // Scope escalation attempt: service asks for more than the subject actually has.
    var subjectWithLittle = UserToken("user-99"); // no scopes at all
    var escalationAttempt = await exchange.ExchangeAsync(
        new TokenExchangeRequest(subjectWithLittle, Audiences.CommentsApi, RequestedScope: "comments.read"),
        callerServiceId: "notification-service");
    Check("cannot mint a scope the subject never had, even though the service is registered for the audience",
        !escalationAttempt.Success && escalationAttempt.Error == TokenExchangeError.NoScopeGrantedAfterNarrowing);

    // Invalid subject token.
    var badSubject = await exchange.ExchangeAsync(
        new TokenExchangeRequest("not-a-real-token", Audiences.CommentsApi, RequestedScope: null),
        callerServiceId: "notification-service");
    Check("malformed subject_token is rejected as invalid_grant, not a crash",
        !badSubject.Success && badSubject.Error == TokenExchangeError.InvalidSubjectToken);

    // Chained delegation: exchange once, then exchange the RESULT again (a second internal
    // hop) and confirm the actor chain grows rather than being overwritten.
    if (happy.Success)
    {
        // The second hop needs a subject_token whose audience matches CollaborateApi to be
        // accepted by ExchangeAsync's validator call in this simplified slice, so we mint a
        // stand-in token that carries the same act claim the first hop produced, on the
        // CollaborateApi audience, to demonstrate the chain-preservation logic in isolation.
        var firstHopClaims = await validator.ValidateAsync(happy.AccessToken!, Audiences.CommentsApi);
        var chainedSubjectToken = issuer.Issue(new TokenIssueRequest(
            Subject: firstHopClaims.Token!.Subject,
            Audience: Audiences.CollaborateApi,
            Scopes: new[] { "comments.read" },
            Lifetime: TimeSpan.FromMinutes(5),
            ActorChainJson: firstHopClaims.Token.ActorChainJson));

        var secondHopRegistry = new InMemoryDelegationRegistry(new[]
        {
            new DelegationGrant("audit-relay-service", Audiences.CommentsApi, new HashSet<string> { "comments.read" }),
        });
        var secondHopExchange = new TokenExchangeService(validator, issuer, secondHopRegistry);
        var secondHop = await secondHopExchange.ExchangeAsync(
            new TokenExchangeRequest(chainedSubjectToken, Audiences.CommentsApi, RequestedScope: null),
            callerServiceId: "audit-relay-service");

        Check("second delegation hop succeeds", secondHop.Success);
        if (secondHop.Success)
        {
            var secondHopValidated = await validator.ValidateAsync(secondHop.AccessToken!, Audiences.CommentsApi);
            var actJson = secondHopValidated.Token?.ActorChainJson ?? "";
            Check("actor chain names BOTH hops (nested, not overwritten)",
                actJson.Contains("audit-relay-service") && actJson.Contains("notification-service"));
        }
    }
}

// ---------------------------------------------------------------------------------------
Console.WriteLine($"\n{passed} passed, {failures.Count} failed.");
if (failures.Count > 0)
{
    Console.WriteLine("Failed: " + string.Join(", ", failures));
    Environment.Exit(1);
}

void RunMintCommand(string which)
{
    var keys = new DevSymmetricSigningKeyProvider(SigningKeyBase64, Issuer);
    var issuer = new TokenIssuer(keys);

    string token = which == "mint-user"
        ? issuer.Issue(new TokenIssueRequest(
            Subject: "user-42", Audience: Audiences.CollaborateApi,
            Scopes: new[] { "comments.read", "comments.write", "documents.read" },
            Lifetime: TimeSpan.FromMinutes(5), FirmId: "firm-7", UserType: "external"))
        : issuer.Issue(new TokenIssueRequest(
            Subject: "notification-service", Audience: Audiences.CollaborateAuth,
            Scopes: new[] { "token-exchange" }, Lifetime: TimeSpan.FromMinutes(30)));

    Console.WriteLine(token);
}
