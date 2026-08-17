using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Auth.Core;

/// <summary>
/// Abstracts where the signing key comes from. The demo implementation below reads a
/// symmetric key from configuration, which is fine for a local slice but is explicitly
/// NOT what CIAS would do in production.
///
/// Production note: CIAS should sign with an asymmetric key (RS256/ES256) held in a KMS/HSM
/// (e.g. AWS KMS) and publish the public half at a JWKS endpoint with a rotating `kid`, so
/// every resource API (Document/Financial/Comments) can validate signatures locally via the
/// standard OIDC discovery + JWKS flow, without ever touching the private key or calling back
/// into CIAS per request. A symmetric key doesn't support that — it's a same-process
/// shortcut for this exercise, not the intended shape.
/// </summary>
public interface ISigningKeyProvider
{
    SecurityKey GetValidationKey();
    SigningCredentials GetSigningCredentials();
    string Issuer { get; }
}

public sealed class DevSymmetricSigningKeyProvider : ISigningKeyProvider
{
    private readonly SymmetricSecurityKey _key;

    public DevSymmetricSigningKeyProvider(string base64Key, string issuer)
    {
        if (string.IsNullOrWhiteSpace(base64Key))
        {
            throw new ArgumentException("Signing key must be configured (Auth:SigningKey).", nameof(base64Key));
        }

        var keyBytes = Convert.FromBase64String(base64Key);
        if (keyBytes.Length < 32)
        {
            // HS256 needs >= 256 bits; refuse to start with a weak dev key rather than
            // silently issuing tokens an attacker could brute-force.
            throw new ArgumentException("Signing key must be at least 256 bits (32 bytes) once decoded.");
        }

        _key = new SymmetricSecurityKey(keyBytes);
        Issuer = issuer;
    }

    public string Issuer { get; }

    public SecurityKey GetValidationKey() => _key;

    public SigningCredentials GetSigningCredentials() =>
        new(_key, SecurityAlgorithms.HmacSha256);
}
