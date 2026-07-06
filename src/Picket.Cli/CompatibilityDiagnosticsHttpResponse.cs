namespace Picket;

internal readonly struct CompatibilityDiagnosticsHttpResponse(string contentType, string body, int statusCode = 200)
{
    internal string ContentType { get; } = contentType;

    internal string Body { get; } = body;

    internal int StatusCode { get; } = statusCode;
}
