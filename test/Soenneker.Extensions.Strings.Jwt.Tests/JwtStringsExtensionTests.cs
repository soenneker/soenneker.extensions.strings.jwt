using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Soenneker.Tests.FixturedUnit;
using System;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Soenneker.Extensions.Strings.Jwt.Tests;

[Collection("Collection")]
public class JwtStringsExtensionTests : FixturedUnitTest
{
    private readonly ILogger<JwtStringsExtensionTests> _logger = new NullLogger<JwtStringsExtensionTests>();


    public JwtStringsExtensionTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public void Default()
    {
    }

    [Fact]
    public void ToJwtExpiration_ValidJwt_ReturnsExpirationDate()
    {
        // Arrange: Create a valid JWT with an expiration time in the future
        long exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        string jwt = CreateJwt(exp);

        // Act
        DateTime? result = jwt.ToJwtExpiration(_logger);

        // Assert
        result.Should().BeCloseTo(DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void ToJwtExpiration_ValidJwtWithoutExp_ReturnsNull()
    {
        // Arrange: JWT without an "exp" claim
        string jwt = CreateJwtWithoutExp();

        // Act
        DateTime? result = jwt.ToJwtExpiration(_logger);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ToJwtExpiration_InvalidJwtFormat_ReturnsNull()
    {
        // Arrange: Malformed JWT (missing parts)
        var jwt = "invalid.jwt.token";

        // Act
        DateTime? result = jwt.ToJwtExpiration(_logger);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ToJwtExpiration_NullOrEmptyJwt_ReturnsNull()
    {
        // Act & Assert
        ((string?) null).ToJwtExpiration(_logger).Should().BeNull();
        "".ToJwtExpiration(_logger).Should().BeNull();
        "   ".ToJwtExpiration(_logger).Should().BeNull();
    }

    [Fact]
    public void ToJwtExpiration_InvalidBase64_ReturnsNull()
    {
        // Arrange: JWT with invalid Base64 payload
        var jwt = "eyJhbGciOiJIUzI1NiJ9.!@#$%^&*().signature";

        // Act
        DateTime? result = jwt.ToJwtExpiration(_logger);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ToJwtExpiration_InvalidExpFormat_ReturnsNull()
    {
        // Arrange: JWT with non-numeric "exp" claim
        string jwt = CreateJwtWithInvalidExp();

        // Act
        DateTime? result = jwt.ToJwtExpiration(_logger);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ToJwtExpiration_ExpiredJwt_ReturnsCorrectDate()
    {
        // Arrange: Expired JWT
        long exp = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        string jwt = CreateJwt(exp);

        // Act
        DateTime? result = jwt.ToJwtExpiration(_logger);

        // Assert
        result.Should().Be(DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime);
    }

    [Fact]
    public void ToJwtExpiration_FutureJwt_ReturnsCorrectDate()
    {
        // Arrange: JWT with expiration in the future
        long exp = DateTimeOffset.UtcNow.AddHours(5).ToUnixTimeSeconds();
        string jwt = CreateJwt(exp);

        // Act
        DateTime? result = jwt.ToJwtExpiration(_logger);

        // Assert
        result.Should().Be(DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime);
    }

    // --- Helper Methods ---

    private static string CreateJwt(long exp)
    {
        var payload = $"{{\"exp\":{exp}}}";
        return EncodeJwt(payload);
    }

    private static string CreateJwtWithoutExp()
    {
        var payload = "{}"; // No "exp" claim
        return EncodeJwt(payload);
    }

    private static string CreateJwtWithInvalidExp()
    {
        var payload = "{\"exp\":\"invalid\"}"; // Non-numeric "exp"
        return EncodeJwt(payload);
    }

    private static string EncodeJwt(string payload)
    {
        var header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

        return $"{Base64UrlEncode(header)}.{Base64UrlEncode(payload)}.signature";
    }

    private static string Base64UrlEncode(string input)
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}