# Collaborate Identity & Authorization Layer — Take-Home Submission

This repo contains both deliverables for the exercise:

- **Part 1 — Design document:** [`docs/DESIGN.md`](docs/DESIGN.md)
- **Part 2 — Targeted implementation:** Option C — *"An endpoint that takes a caller's token
  and issues a new, narrower token scoped to a specific downstream user."* I implemented the
  internal service-to-service on-behalf-of scenario (a notification service acting after a
  comment is posted), since that's the one the exercise specifically names as the
  confused-deputy risk worth demonstrating.

## What's here

```
src/Collaborate.Auth.Core/   Pure domain logic: token issuance/validation, scope narrowing,
                              the delegation registry, and the token-exchange service. No
                              ASP.NET Core dependency — this is the part worth unit testing.
src/Collaborate.Auth.Api/    ASP.NET Core minimal API: POST /api/token-exchange, wired up
                              through ordinary authentication/authorization middleware.
tests/Collaborate.Auth.Tests/ Executable verification suite (see "Offline build note" below
                              for why it isn't xunit) covering the domain logic end to end.
docs/DESIGN.md                Part 1.
```

## Running it

```bash
dotnet build
dotnet run --project tests/Collaborate.Auth.Tests            # runs the verification suite
dotnet run --project src/Collaborate.Auth.Api                 # starts the API on :5047 (see launchSettings.json)
```

With the API running, mint a couple of demo tokens and try the endpoint:

```bash
USER_TOKEN=$(dotnet run --project tests/Collaborate.Auth.Tests --no-build -- mint-user)
SERVICE_TOKEN=$(dotnet run --project tests/Collaborate.Auth.Tests --no-build -- mint-service)

curl -s -X POST http://localhost:5047/api/token-exchange \
  -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",\"subject_token\":\"$USER_TOKEN\",\"audience\":\"comments-api\"}"
```

Decode the resulting `access_token` (e.g. at jwt.io) and you'll see: `aud` narrowed to
`comments-api` only, `scope` narrowed from the user's full `comments.read comments.write` down
to just `comments.read` (all `notification-service` is trusted for), `sub` still the original
user (`user-42`), and an `act` claim naming `notification-service` as the actor. Try the same
call with `"audience":"financial-api"` and it's rejected with 403 — `notification-service` has
no registered grant for that audience at all.

## Offline build note

This was authored in a sandboxed environment with **no NuGet registry access** (`nuget.org`
was unreachable — a deliberate network policy in that sandbox, not a transient failure). That
shaped two implementation choices which I want to be upfront about, since neither is what I'd
actually ship:

1. **`/lib` vendors five `Microsoft.IdentityModel.*` assemblies** (`JsonWebTokens`, `Tokens`,
   `Logging`, `Abstractions`, `System.IdentityModel.Tokens.Jwt`, all v7.7.3) instead of
   referencing them as ordinary `PackageReference`s. They're the *exact* official binaries —
   extracted from the .NET 8 SDK's own bundled `dotnet-user-jwts` tool, which happens to ship
   them locally — not reimplementations. `Collaborate.Auth.Core.csproj` has a comment showing
   the one-line `PackageReference` this should collapse back into the moment NuGet is
   reachable; `NuGet.Config` clearing package sources is what makes `dotnet build` skip even
   trying to reach the network.
2. **No `Microsoft.AspNetCore.Authentication.JwtBearer` package** — it wasn't vendored
   anywhere available, so `Authentication/BearerTokenAuthenticationHandler.cs` is a small
   custom `AuthenticationHandler<TOptions>` instead of `AddJwtBearer(...)`. It still does zero
   hand-rolled parsing or crypto — every byte of signature verification goes through
   `JsonWebTokenHandler.ValidateTokenAsync` (the same engine `AddJwtBearer` uses internally).
   The file's doc comment shows exactly what the `AddJwtBearer(...)` call should look like
   once the package is available; swapping it in is a delete-and-paste, not a redesign.
3. **Tests aren't xunit** for the same reason (`Microsoft.NET.Test.Sdk` / `xunit` are NuGet
   packages too, and weren't vendored). `tests/Collaborate.Auth.Tests/Program.cs` is a plain
   console app with a `Check(name, condition)` helper that reads like a `[Fact]` per case —
   21 checks, all currently passing, run with `dotnet run --project tests/Collaborate.Auth.Tests`.
   Migrating to xunit later is a mechanical rename, not new test-writing.

I'm calling this out explicitly rather than quietly working around it, because "the sandbox
can't reach NuGet" is exactly the kind of environment constraint I'd flag in a real PR rather
than silently paper over — and because the AI-usage section below is partly about this same
judgment call.

## Design choices specific to this slice

**Why Token Exchange (RFC 8693) and not something bespoke.** The exercise's own on-behalf-of
scenario — an internal service acting after a user's action, and needing the downstream call
scoped to that user and attributable to them — is precisely what RFC 8693's `subject_token` +
`act` claim mechanism was designed for. `TokenExchangeService` implements a simplified version
of it (one grant type, one token type, no full negotiation matrix) rather than the complete
spec, since the exercise only calls for one delegation scenario.

**Where the confused-deputy protection actually lives.** It's not any single check — it's the
combination, all enforced server-side in `TokenExchangeService`, never left to the caller's
honesty:
- The calling service must be **pre-registered** to act for the requested audience at all
  (`IDelegationRegistry`) — an unregistered `(service, audience)` pair is refused outright.
- Granted scope is the **intersection** of requested ∩ subject's actual scope ∩ the service's
  registered max — it can only narrow, never escalate, even if the service asks for more.
- The issued token's `aud` is the **single** requested downstream API, so it can't be replayed
  elsewhere (the test suite verifies this directly: a token minted for `comments-api` fails
  validation against `documents-api`).
- **Authorization downstream is always against `sub`** (the original user), never the calling
  service's own identity — this is the part that actually matters. The audience/scope
  restrictions limit blast radius, but the reason a notification service acting on a comment
  can't read a document the user *can't* read is that the resource API checks the user's
  permissions, not the service's. A service with broad database access but a correctly-scoped
  token is still constrained by what's *in* the token.
- The `act` claim **nests rather than overwrites** on each hop, so a two-hop delegation chain
  stays fully attributable back to the human who triggered it (`TokenExchangeService.cs`,
  `BuildActorChain`, and the "second delegation hop" test).
- Tokens are **short-lived (60s)** — long enough for one downstream call, not a session.

**What I intentionally didn't build.** No JWKS/key-rotation story (a single symmetric dev key,
clearly marked as such in `appsettings.json` and `ISigningKeyProvider.cs`), no persistence for
the delegation registry (in-memory, seeded), no rate limiting, no distributed cache for
revocation. All of these are real production requirements — they're addressed as design
decisions in `docs/DESIGN.md`, not re-litigated in code here, per the exercise's own guidance
to prioritize "interfaces, contracts, and correctness over completeness."

## AI usage

I used Claude to help produce both the design document and this implementation. In the
interest of the exercise's request for a genuine, specific account of where AI helped, where
I'd push back on it, and where it shouldn't be trusted in this domain — **the sections below
are a starting draft for me to personalize with my own honest specifics before submitting**,
not a finished answer. Notes on what's real and worth keeping as-is: the offline-NuGet
constraint above was a genuine environment limitation discovered and worked around during this
session (verified by actually running `dotnet build`/`dotnet test` against it), not a
hypothetical.

- **Where AI helped:** scaffolding the ASP.NET Core project structure, drafting the RFC 8693
  field naming, and writing the assertion-based test harness once xunit turned out to be
  unavailable.
- **Where I'd want to double check / push back on AI output before submitting this as my own
  work:** the specific TTL numbers (60s for delegated tokens, 5min for session tokens) are
  reasonable defaults, not benchmarked against Collaborate's actual traffic patterns — I'd
  want to verify these against real latency budgets before treating them as anything more than
  a starting point. Same for the in-memory delegation registry's demo grants — they're
  illustrative, not a real access model.
- **How I'd guide other engineers using AI on this system:** treat AI-suggested token
  lifetimes, scope models, and "fail open vs. fail closed" defaults as proposals to be
  reviewed against the actual compliance/audit requirements of an audit-and-assurance product,
  not as settled answers — this is a domain where the cost of a wrong default (a permission
  that should have been revoked but wasn't, a token scoped too broadly) is a real security
  incident, not a bug ticket.
- **Where AI should not be trusted in this domain:** generating or modifying anything that
  touches actual cryptographic signing/verification logic without using the standard library
  primitives directly (this repo deliberately routes 100% of that through
  `JsonWebTokenHandler`, never hand-written); and any claim about "this is how OAuth2/OIDC
  compliance works" should be checked against the actual RFCs rather than taken on confidence,
  since subtly wrong auth code is exactly the kind of bug that looks correct in a demo and
  fails in production.
