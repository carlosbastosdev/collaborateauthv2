using System.Text.Json.Serialization;

namespace Collaborate.Auth.Api.Contracts;

/// <summary>
/// Field names follow RFC 8693 (OAuth 2.0 Token Exchange) so this endpoint reads as a
/// recognizable token-exchange grant rather than a bespoke shape, even though this slice
/// only implements the one internal-delegation scenario described in the design doc, not
/// the full grant-type/token-type negotiation the RFC allows for.
/// </summary>
public sealed record TokenExchangeHttpRequest(
    [property: JsonPropertyName("grant_type")] string GrantType,
    [property: JsonPropertyName("subject_token")] string SubjectToken,
    [property: JsonPropertyName("subject_token_type")] string? SubjectTokenType,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("scope")] string? Scope);

public sealed record TokenExchangeHttpResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("issued_token_type")] string IssuedTokenType,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] int ExpiresIn,
    [property: JsonPropertyName("scope")] string Scope);

public sealed record TokenExchangeHttpError(
    [property: JsonPropertyName("error")] string Error,
    [property: JsonPropertyName("error_description")] string ErrorDescription);

public static class TokenExchangeConstants
{
    public const string GrantType = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
}
