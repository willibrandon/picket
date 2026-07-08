using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Sources;

internal static class S3RequestSigner
{
    private const string Algorithm = "AWS4-HMAC-SHA256";
    private const string EmptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const string ServiceName = "s3";

    internal static void Sign(HttpRequestMessage request, S3SourceOptions options, DateTimeOffset timestamp)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        Uri requestUri = request.RequestUri ?? throw new InvalidOperationException("S3 request URI is not set.");
        string longDate = timestamp.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        string shortDate = timestamp.UtcDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        request.Headers.Host = requestUri.IsDefaultPort
            ? requestUri.Host
            : string.Concat(requestUri.Host, ":", requestUri.Port.ToString(CultureInfo.InvariantCulture));
        request.Headers.Remove("x-amz-content-sha256");
        request.Headers.Remove("x-amz-date");
        request.Headers.Remove("x-amz-security-token");
        request.Headers.TryAddWithoutValidation("x-amz-content-sha256", EmptyPayloadHash);
        request.Headers.TryAddWithoutValidation("x-amz-date", longDate);
        if (options.SessionToken.Length != 0)
        {
            request.Headers.TryAddWithoutValidation("x-amz-security-token", options.SessionToken);
        }

        string signedHeaders = options.SessionToken.Length == 0
            ? "host;x-amz-content-sha256;x-amz-date"
            : "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
        string canonicalHeaders = CreateCanonicalHeaders(request, options);
        string canonicalRequest = string.Concat(
            "GET\n",
            requestUri.AbsolutePath,
            "\n",
            CreateCanonicalQuery(requestUri),
            "\n",
            canonicalHeaders,
            "\n",
            signedHeaders,
            "\n",
            EmptyPayloadHash);
        string credentialScope = string.Concat(shortDate, "/", options.Region, "/", ServiceName, "/aws4_request");
        string stringToSign = string.Concat(
            Algorithm,
            "\n",
            longDate,
            "\n",
            credentialScope,
            "\n",
            ToHex(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest))));
        byte[] signingKey = CreateSigningKey(options.SecretAccessKey, shortDate, options.Region);
        string signature = ToHex(HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(stringToSign)));
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            string.Concat(
                Algorithm,
                " Credential=",
                options.AccessKeyId,
                "/",
                credentialScope,
                ", SignedHeaders=",
                signedHeaders,
                ", Signature=",
                signature));
    }

    private static string CreateCanonicalHeaders(HttpRequestMessage request, S3SourceOptions options)
    {
        var builder = new StringBuilder();
        builder.Append("host:");
        builder.Append(request.Headers.Host);
        builder.Append('\n');
        builder.Append("x-amz-content-sha256:");
        builder.Append(EmptyPayloadHash);
        builder.Append('\n');
        builder.Append("x-amz-date:");
        builder.Append(GetHeaderValue(request, "x-amz-date"));
        builder.Append('\n');
        if (options.SessionToken.Length != 0)
        {
            builder.Append("x-amz-security-token:");
            builder.Append(options.SessionToken);
            builder.Append('\n');
        }

        return builder.ToString();
    }

    private static string CreateCanonicalQuery(Uri requestUri)
    {
        string query = requestUri.Query;
        if (query.Length == 0)
        {
            return string.Empty;
        }

        string[] parameters = query[1..].Split('&', StringSplitOptions.RemoveEmptyEntries);
        Array.Sort(parameters, StringComparer.Ordinal);
        return string.Join('&', parameters);
    }

    private static string GetHeaderValue(HttpRequestMessage request, string headerName)
    {
        return request.Headers.TryGetValues(headerName, out IEnumerable<string>? values)
            ? string.Join(',', values)
            : string.Empty;
    }

    private static byte[] CreateSigningKey(string secretAccessKey, string shortDate, string region)
    {
        byte[] dateKey = HMACSHA256.HashData(Encoding.UTF8.GetBytes(string.Concat("AWS4", secretAccessKey)), Encoding.UTF8.GetBytes(shortDate));
        byte[] regionKey = HMACSHA256.HashData(dateKey, Encoding.UTF8.GetBytes(region));
        byte[] serviceKey = HMACSHA256.HashData(regionKey, Encoding.UTF8.GetBytes(ServiceName));
        return HMACSHA256.HashData(serviceKey, Encoding.UTF8.GetBytes("aws4_request"));
    }

    private static string ToHex(ReadOnlySpan<byte> value)
    {
        return Convert.ToHexStringLower(value);
    }
}
