using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Auth.Core;

public interface ITokenIssuer
{
    string Issue(TokenIssueRequest request);
}

/// <summary>
/// Mints access tokens using <see cref="JsonWebTokenHandler"/> — the same token-creation
/// engine ASP.NET Core's JwtBearer stack and IdentityServer are built on. No token parsing,
/// serialization, or signing is hand-rolled here; this class only decides *what claims go in*,
/// which is business logic, not cryptography.
/// </summary>
public sealed class TokenIssuer : ITokenIssuer
{
    private readonly ISigningKeyProvider _keys;
    private readonly JsonWebTokenHandler _handler = new();

    public TokenIssuer(ISigningKeyProvider keys) => _keys = keys;

    public string Issue(TokenIssueRequest request)
    {
        var now = DateTime.UtcNow;

        var claims = new Dictionary<string, object>
        {
            ["scope"] = string.Join(' ', request.Scopes),
        };

        if (request.FirmId is not null) claims["firm_id"] = request.FirmId;
        if (request.UserType is not null) claims["user_type"] = request.UserType;
        if (request.Azp is not null) claims["azp"] = request.Azp;

        // RFC 8693 actor claim. If the subject token we're delegating from already carried
        // its own "act" (a prior delegation hop), request.ActorChainJson is that raw JSON and
        // gets nested one level deeper here — the chain grows, it never gets overwritten, so
        // "who is really making this call" stays reconstructable however many hops deep.
        if (request.ActorChainJson is not null)
        {
            claims["act"] = System.Text.Json.JsonSerializer.Deserialize<object>(request.ActorChainJson)!;
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _keys.Issuer,
            Audience = request.Audience,
            Subject = new System.Security.Claims.ClaimsIdentity(
                new[] { new System.Security.Claims.Claim("sub", request.Subject) }),
            IssuedAt = now,
            NotBefore = now,
            Expires = now.Add(request.Lifetime),
            SigningCredentials = _keys.GetSigningCredentials(),
            Claims = claims,
        };

        return _handler.CreateToken(descriptor);
    }
}
