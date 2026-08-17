using Collaborate.Auth.Core;
using Microsoft.AspNetCore.Authentication;

namespace Collaborate.Auth.Api.Authentication;

public sealed class BearerTokenAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>The audience this scheme instance expects incoming tokens to carry.</summary>
    public string Audience { get; set; } = Audiences.CollaborateAuth;
}
