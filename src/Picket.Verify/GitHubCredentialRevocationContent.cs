using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Picket.Verify;

/// <summary>
/// Streams the GitHub credential revocation payload without retaining an uncleared serialized copy.
/// </summary>
internal sealed class GitHubCredentialRevocationContent : HttpContent
{
    private readonly string[] _credentials;

    /// <summary>
    /// Creates JSON request content for the supplied credentials.
    /// </summary>
    /// <param name="credentials">The credentials to serialize.</param>
    internal GitHubCredentialRevocationContent(string[] credentials)
    {
        _credentials = credentials ?? throw new ArgumentNullException(nameof(credentials));
        Headers.ContentType = new MediaTypeHeaderValue("application/json");
    }

    /// <inheritdoc />
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        return SerializeToStreamAsync(stream, context, CancellationToken.None);
    }

    /// <inheritdoc />
    protected override async Task SerializeToStreamAsync(
        Stream stream,
        TransportContext? context,
        CancellationToken cancellationToken)
    {
        var buffer = new ArrayBufferWriter<byte>();
        try
        {
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteStartArray("credentials");
                for (int i = 0; i < _credentials.Length; i++)
                {
                    writer.WriteStringValue(_credentials[i]);
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            await stream.WriteAsync(buffer.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (MemoryMarshal.TryGetArray(buffer.WrittenMemory, out ArraySegment<byte> segment))
            {
                segment.AsSpan().Clear();
            }
        }
    }

    /// <inheritdoc />
    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}
