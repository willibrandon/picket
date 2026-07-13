namespace Picket.Compat;

internal static class EmbeddedPicketExperimentalConfig
{
    internal const string SourceVersion = "picket-experimental-2026-07-13";

    internal static string Toml { get; } = CreateToml();

    private static string CreateToml()
    {
        string bearerToken = CreateExample("v7Kp3mN9qR2tX5wZ8cF4hJ6s", "L1dG0bV3yU7aE9iO");
        string sessionCookie = CreateExample("M8rQ2vL7xP4nK9sD6fH3jT5w", "B0cY1uA7eG4iN2oZ");

        return $$"""
title = "picket experimental rule pack"

[[rules]]
id = "picket-experimental-bearer-token"
description = "Detected an opaque bearer token in an HTTP authorization header."
regex = '''(?i)\bauthorization\s*[:=]\s*["']?bearer\s+([A-Za-z0-9._~+/-]{24,}={0,2})'''
secretGroup = 1
entropy = 3.5
randomnessThreshold = 0.55
keywords = ["authorization", "bearer"]
tags = ["picket", "experimental", "http", "bearer-token"]
severity = "critical"
confidence = "low"
rulePack = "picket-experimental"
provider = "HTTP"
documentationUrl = "https://www.rfc-editor.org/rfc/rfc6750"
examples = ["Authorization: Bearer {{bearerToken}}"]
negativeExamples = ["Authorization: Bearer ${ACCESS_TOKEN}"]

[[rules]]
id = "picket-experimental-session-cookie"
description = "Detected an opaque session or authentication token in an HTTP cookie header."
regex = '''(?i)\b(?:set-cookie|cookie)\s*:\s*[^\r\n;]{0,128}(?:session|auth|token)[_-]?(?:id|key)?=([A-Za-z0-9._~+/-]{24,}={0,2})'''
secretGroup = 1
entropy = 3.5
randomnessThreshold = 0.55
keywords = ["set-cookie", "cookie", "session", "auth", "token"]
tags = ["picket", "experimental", "http", "cookie", "session"]
severity = "high"
confidence = "low"
rulePack = "picket-experimental"
provider = "HTTP"
documentationUrl = "https://owasp.org/www-community/controls/SecureCookieAttribute"
examples = ["Set-Cookie: session_id={{sessionCookie}}; Secure; HttpOnly"]
negativeExamples = ["Set-Cookie: session_id=${SESSION_ID}; Secure; HttpOnly"]
""";
    }

    private static string CreateExample(params string[] parts)
    {
        return string.Concat(parts);
    }
}
