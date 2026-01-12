using Microsoft.Extensions.Logging;
using Soenneker.Extensions.Arrays.Bytes;
using Soenneker.Extensions.String;
using System;
using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.Contracts;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Soenneker.Extensions.Strings.Jwt;

/// <summary>
/// A collection of helpful string extension methods around JWTs
/// </summary>
public static class JwtStringsExtension
{
    private static ReadOnlySpan<byte> ExpUtf8 => "exp"u8;

    /// <summary>
    /// Tries to extract the expiration date from a JSON Web Token (JWT) efficiently.
    /// Uses Base64Url decoding + Utf8JsonReader to avoid intermediate string/JsonDocument allocations.
    /// </summary>
    /// <param name="jwt">The JWT string.</param>
    /// <param name="logger">An optional logger to record critical errors if parsing fails.</param>
    /// <returns>The expiration date of the JWT as a <see cref="DateTime"/> if valid; otherwise, <c>null</c>.</returns>
    [Pure, MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static DateTime? ToJwtExpiration(this string jwt, ILogger? logger = null)
    {
        if (jwt.IsNullOrWhiteSpace())
            return null;

        try
        {
            // JWT: header.payload.signature
            ReadOnlySpan<char> span = jwt.AsSpan();

            int firstDot = span.IndexOf('.');
            if (firstDot <= 0)
                return null;

            ReadOnlySpan<char> afterFirst = span.Slice(firstDot + 1);
            int secondDotRel = afterFirst.IndexOf('.');
            if (secondDotRel <= 0)
                return null;

            ReadOnlySpan<char> payloadB64Url = afterFirst.Slice(0, secondDotRel);
            if (payloadB64Url.IsEmpty)
                return null;

            // Decode Base64Url payload into rented byte[]
            int maxDecodedLen = GetMaxBase64DecodedLength(payloadB64Url.Length);
            byte[] rented = ArrayPool<byte>.Shared.Rent(maxDecodedLen);

            try
            {
                // Base64Url in System.Buffers.Text handles '-'/'_' and missing padding
                OperationStatus status = Base64Url.DecodeFromChars(payloadB64Url, rented, out int charsConsumed, out int bytesWritten, isFinalBlock: true);

                if (status != OperationStatus.Done || charsConsumed != payloadB64Url.Length || bytesWritten <= 0)
                    return null;

                // Scan JSON for "exp" without JsonDocument allocations
                var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(rented, 0, bytesWritten), isFinalBlock: true, state: default);

                while (reader.Read())
                {
                    if (reader.TokenType != JsonTokenType.PropertyName)
                        continue;

                    if (!reader.ValueTextEquals(ExpUtf8))
                        continue;

                    if (!reader.Read())
                        return null;

                    if (reader.TokenType != JsonTokenType.Number || !reader.TryGetInt64(out long expUnix))
                        return null;

                    return DateTimeOffset.FromUnixTimeSeconds(expUnix)
                                         .UtcDateTime;
                }

                return null;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented, clearArray: false);
            }
        }
        catch (Exception e)
        {
            logger?.LogCritical(e, "Error getting the JWT expiration");
            return null;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetMaxBase64DecodedLength(int base64CharLen)
    {
        // Max decoded bytes for base64/base64url input (with or without padding):
        // ceil(n/4) * 3
        // Use integer math: ((n + 3) / 4) * 3
        return ((base64CharLen + 3) >> 2) * 3;
    }
}