using Collaborate.Auth.Core;

namespace Collaborate.Auth.Tests;

/// <summary>Shared dev signing key for tests — not the same key as appsettings.json on
/// purpose, so a test run never depends on the API project's configuration.</summary>
internal static class TestKeys
{
    private const string SigningKeyBase64 = "ZjE4YzJlOTMtYzQ4Yy00YTI5LTllZDgtYjcwNDllOTBiZjc4";
    private const string Issuer = "https://auth.collaborate.local";

    public static ISigningKeyProvider Provider() => new DevSymmetricSigningKeyProvider(SigningKeyBase64, Issuer);
}
