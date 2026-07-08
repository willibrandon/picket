using System.Globalization;
using System.Text.Json;

namespace Picket.Sources;

/// <summary>
/// Reads provider metadata JSON with a fixed byte ceiling.
/// </summary>
internal static class RemoteJsonDocumentReader
{
    internal const long DefaultMaxMetadataBytes = 10_000_000;

    /// <summary>
    /// Parses a JSON metadata response after applying the default metadata byte cap.
    /// </summary>
    /// <param name="content">The HTTP response content.</param>
    /// <param name="target">A short target name used in warnings.</param>
    /// <param name="warningSink">The optional warning sink.</param>
    /// <param name="cancellationToken">A token that can cancel metadata parsing.</param>
    /// <returns>The parsed JSON document.</returns>
    internal static async Task<JsonDocument> ReadAsync(
        HttpContent content,
        string target,
        Action<string>? warningSink,
        CancellationToken cancellationToken)
    {
        return await ReadAsync(
            content,
            target,
            warningSink,
            DefaultMaxMetadataBytes,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Parses a JSON metadata response after applying a caller supplied byte cap.
    /// </summary>
    /// <param name="content">The HTTP response content.</param>
    /// <param name="target">A short target name used in warnings.</param>
    /// <param name="warningSink">The optional warning sink.</param>
    /// <param name="maxBytes">The maximum number of metadata bytes to read.</param>
    /// <param name="cancellationToken">A token that can cancel metadata parsing.</param>
    /// <returns>The parsed JSON document.</returns>
    internal static async Task<JsonDocument> ReadAsync(
        HttpContent content,
        string target,
        Action<string>? warningSink,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxBytes, 0);

        if (content.Headers.ContentLength is long contentLength && contentLength > maxBytes)
        {
            ThrowTooLarge(target, warningSink, maxBytes, contentLength);
        }

        using Stream stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var cappedStream = new CappedReadStream(stream, maxBytes, target);
        try
        {
            return await JsonDocument.ParseAsync(
                cappedStream,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (RemoteMetadataTooLargeException ex)
        {
            warningSink?.Invoke(ex.Message);
            throw;
        }
    }

    private static void ThrowTooLarge(
        string target,
        Action<string>? warningSink,
        long maxBytes,
        long? contentLength)
    {
        string message = CreateTooLargeMessage(target, maxBytes, contentLength);
        warningSink?.Invoke(message);
        throw new RemoteMetadataTooLargeException(message);
    }

    private static string CreateTooLargeMessage(string target, long maxBytes, long? contentLength)
    {
        if (contentLength.HasValue)
        {
            return string.Create(
                CultureInfo.InvariantCulture,
                $"skipping {target} because remote metadata response reported {contentLength.Value} bytes, exceeding the {maxBytes} byte metadata cap");
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"skipping {target} because remote metadata response exceeded the {maxBytes} byte metadata cap");
    }
}
