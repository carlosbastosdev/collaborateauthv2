using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Auth.Core;

public interface ITokenValidator
{
    Task<TokenValidationOutcome> ValidateAsync(string token, string expectedAudience, CancellationToken ct = default);
}

/// <summary>
/// Validates access tokens using <see cref="JsonWebTokenHandler"/> — signature verification,
/// expiry, issuer and audience checks are all performed by the library via
/// <see cref="TokenValidationParameters"/>. This is deliberately the one and only place a raw
/// JWT string gets parsed in the whole service; everything else works off
/// <see cref="ValidatedToken"/>.
/// </summary>
public sealed class TokenValidator : ITokenValidator
{
    private readonly ISigningKeyProvider _keys;
    private readonly JsonWebTokenHandler _handler = new();

    public TokenValidator(ISigningKeyProvider keys) => _keys = keys;

    public async Task<TokenValidationOutcome> ValidateAsync(string token, string expectedAudience, CancellationToken ct = default)
    {
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = _keys.Issuer,
            ValidateIssuer = true,
            ValidAudience = expectedAudience,
            ValidateAudience = true,
            IssuerSigningKey = _keys.GetValidationKey(),
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        TokenValidationResult result;
        try
        {
            result = await _handler.ValidateTokenAsync(token, parameters);
        }
        catch (Exception ex)
        {
            // ValidateTokenAsync normally reports failures via TokenValidationResult.IsValid
            // rather than throwing, but malformed input (e.g. not even JWT-shaped) can throw
            // before it gets that far — treat both paths as "invalid token", never as a crash.
            return TokenValidationOutcome.Failure($"Malformed token: {ex.Message}");
        }

        if (!result.IsValid)
        {
            return TokenValidationOutcome.Failure(result.Exception?.Message ?? "Token validation failed.");
        }

        var identity = result.ClaimsIdentity;
        string? Get(string type) => identity.FindFirst(type)?.Value;

        var scopeClaim = Get("scope") ?? string.Empty;
        var scopes = scopeClaim
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.Ordinal);

        var subject = Get("sub");
        if (string.IsNullOrEmpty(subject))
        {
            return TokenValidationOutcome.Failure("Token has no 'sub' claim.");
        }

        var expClaim = Get("exp");
        var expiresAt = expClaim is not null && long.TryParse(expClaim, out var expUnix)
            ? DateTimeOffset.FromUnixTimeSeconds(expUnix)
            : DateTimeOffset.UtcNow;

        var validated = new ValidatedToken(
            Subject: subject,
            FirmId: Get("firm_id"),
            UserType: Get("user_type"),
            Azp: Get("azp"),
            Scopes: scopes,
            ActorChainJson: Get("act"),
            ExpiresAt: expiresAt);

        return TokenValidationOutcome.Success(validated);
    }
}
