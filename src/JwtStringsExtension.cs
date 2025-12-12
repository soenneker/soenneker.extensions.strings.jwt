using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using Soenneker.Extensions.String;
using Soenneker.Extensions.Arrays.Bytes;

namespace Soenneker.Extensions.Strings.Jwt;

/// <summary>
/// A collection of helpful string extension methods around JWTs
/// </summary>
public static class JwtStringsExtension
{
    /// <summary>
    /// Tries to extract the expiration date from a JSON Web Token (JWT) efficiently. This method avoids unnecessary allocations.
    /// </summary>
    /// <param name="jwt">The JWT string.</param>
    /// <param name="logger">An optional logger to record critical errors if parsing fails.</param>
    /// <returns>The expiration date of the JWT as a <see cref="DateTime"/> if valid; otherwise, <c>null</c> if parsing fails.</returns>
    public static DateTime? ToJwtExpiration(this string jwt, ILogger? logger = null)
    {
        if (jwt.IsNullOrWhiteSpace())
            return null;

        try
        {
            // JWT format: header.payload.signature
            // Parse manually to avoid Split allocation
            ReadOnlySpan<char> jwtSpan = jwt.AsSpan();
            int firstDot = jwtSpan.IndexOf('.');
            if (firstDot < 0)
                return null;

            int secondDot = jwtSpan.Slice(firstDot + 1).IndexOf('.');
            if (secondDot < 0)
                return null;

            // Extract payload (between first and second dot)
            ReadOnlySpan<char> payloadBase64 = jwtSpan.Slice(firstDot + 1, secondDot);
            string payloadBase64String = payloadBase64.ToString();

            // Decode Base64Url payload (second part of JWT)
            string payloadJson = PadBase64(payloadBase64String).ToBytesFromBase64().ToStr();

            using JsonDocument document = JsonDocument.Parse(payloadJson);

            if (!document.RootElement.TryGetProperty("exp", out JsonElement expElement))
                return null;

            if (expElement.ValueKind != JsonValueKind.Number || !expElement.TryGetInt64(out long expUnix))
                return null;

            // Convert Unix timestamp to DateTime
            return DateTimeOffset.FromUnixTimeSeconds(expUnix).UtcDateTime;
        }
        catch (Exception e)
        {
            logger?.LogCritical(e, "Error getting the JWT expiration");
            return null;
        }
    }

    /// <summary>
    /// Ensures proper Base64 padding for decoding.
    /// </summary>
    private static string PadBase64(string base64)
    {
        int padding = base64.Length % 4;
        return padding == 0 ? base64 : base64 + new string('=', 4 - padding);
    }
}