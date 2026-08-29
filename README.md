[![](https://img.shields.io/nuget/v/soenneker.extensions.strings.jwt.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.strings.jwt/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.strings.jwt/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.strings.jwt/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.extensions.strings.jwt.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.strings.jwt/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.strings.jwt/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.strings.jwt/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Extensions.Strings.Jwt
String extension methods for inspecting and extracting data from JSON Web Tokens without unnecessary payload materialization.

## Installation

```bash
dotnet add package Soenneker.Extensions.Strings.Jwt
```

## Usage

```csharp
using Soenneker.Extensions.Strings.Jwt;

DateTime? expiresUtc = jwt.ToJwtExpiration(logger);
```

`ToJwtExpiration()` decodes only the payload, reads an integer `exp` claim as Unix seconds, and returns a UTC `DateTime`. Missing segments, malformed Base64URL/JSON, a missing or non-integer `exp`, and out-of-range timestamps all return `null`. Unexpected exceptions are logged at `Critical` when a logger is supplied.

This method does **not** validate the JWT signature, issuer, audience, algorithm, or current expiration state. Use it only to inspect a token whose trust has been established elsewhere.
