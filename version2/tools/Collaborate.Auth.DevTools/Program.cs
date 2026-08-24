// Mints demo tokens for manual curl testing against the running API — split out of the test
// project because that project is now a real xunit library (v2), not an executable.
//
// Usage:
//   dotnet run --project tools/Collaborate.Auth.DevTools -- mint-user
//   dotnet run --project tools/Collaborate.Auth.DevTools -- mint-service
//
// IMPORTANT: this must use the SAME signing key as src/Collaborate.Auth.Api/appsettings.json
// (Auth:SigningKey) for the tokens it mints to validate against the running API — it does
// NOT read that file, the key is duplicated here deliberately so this tool has zero
// dependency on the Api project's configuration. If you change one, change both.
using Collaborate.Auth.Core;

const string SigningKeyBase64 = "N2Y5YzFlZDctNTFmMS00MTgxLWEwZjItYzQwYjE1NGJjZjNi";
const string Issuer = "https://auth.collaborate.local";

if (args.Length != 1 || args[0] is not ("mint-user" or "mint-service"))
{
    Console.Error.WriteLine("Usage: dotnet run -- <mint-user|mint-service>");
    Environment.Exit(1);
    return;
}

var keys = new DevSymmetricSigningKeyProvider(SigningKeyBase64, Issuer);
var issuer = new TokenIssuer(keys);

var token = args[0] == "mint-user"
    ? issuer.Issue(new TokenIssueRequest(
        Subject: "user-42",
        Audience: Audiences.CollaborateApi,
        Scopes: new[] { "comments.read", "comments.write", "documents.read" },
        Lifetime: TimeSpan.FromMinutes(5),
        FirmId: "firm-7",
        UserType: "external"))
    : issuer.Issue(new TokenIssueRequest(
        Subject: "notification-service",
        Audience: Audiences.CollaborateAuth,
        Scopes: new[] { "token-exchange" },
        Lifetime: TimeSpan.FromMinutes(30)));

Console.WriteLine(token);
