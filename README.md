[![](https://img.shields.io/nuget/v/soenneker.extensions.strings.jwt.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.strings.jwt/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.strings.jwt/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.strings.jwt/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.extensions.strings.jwt.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.strings.jwt/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.strings.jwt/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.strings.jwt/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Extensions.Strings.Jwt
A collection of helpful string extension methods around JWTs.

## Installation

```bash
dotnet add package Soenneker.Extensions.Strings.Jwt
```

## Quick start

```csharp
using Soenneker.Extensions.Strings.Jwt;

string jwt = "example";
var result = jwt.ToJwtExpiration();
```

## Common operations

- `ToJwtExpiration()` - Tries to extract the expiration date from a JSON Web Token (JWT) efficiently. Uses Base64Url decoding + Utf8JsonReader to avoid intermediate string/JsonDocument allocations. Returns the expiration date of the JWT as a `DateTime` if valid; otherwise, `null`.
