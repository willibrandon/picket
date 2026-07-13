namespace Picket.Compat;

internal static class EmbeddedPicketStrictConfig
{
    internal const string SourceVersion = "picket-strict-2026-07-13";

    internal static string Toml { get; } = CreateToml();

    private static string CreateToml()
    {
        string connectionStringPassword = CreateExample("S7r!ct-", "N4tive-42");
        string basicAuthorization = CreateExample("cGlja2V0LXVzZXI6", "UzdyIWN0LU5hdGl2ZS00Mg==");
        string basicAuthorizationPlaceholder = CreateExample("dXNlcm5hbWU6", "cGFzc3dvcmQ=");
        string sasSignature = CreateExample("Q2hhbmdlTWVOb3RSZWFs", "U2lnbmF0dXJlMTIzNDU2Nzg5MA%3D%3D");

        return $$"""
title = "picket strict rule pack"

[[rules]]
id = "picket-strict-connection-string-password"
description = "Detected a password embedded in a semicolon-delimited connection string."
regex = '''(?i)\b(?:password|pwd)\s*=\s*(["']?[^\r\n;"']{8,256}["']?)'''
secretGroup = 1
entropy = 2.5
keywords = ["password", "pwd"]
tags = ["picket", "strict", "connection-string", "password"]
severity = "critical"
confidence = "medium"
rulePack = "picket-strict"
provider = "Database"
documentationUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
examples = ["Server=db.internal;User Id=app;Password={{connectionStringPassword}};Encrypt=true"]
negativeExamples = [
    "Server=db.internal;Integrated Security=true;Encrypt=true",
    "Server=db.internal;User Id=app;Password=${DATABASE_PASSWORD};Encrypt=true",
    "Server=db.internal;User Id=app;Password=ChangeMe123!;Encrypt=true",
]

[[rules.allowlists]]
regexTarget = "secret"
regexes = ['''(?i)^["']?(?:change(?:it|me)[0-9!@#._-]*|dummy|example|passw0rd|password|placeholder|test|<[^>]+>|\$\{[^}]+})["']?$''']

[[rules]]
id = "picket-strict-basic-authorization"
description = "Detected an HTTP Basic authorization credential."
regex = '''(?i)\b(?:authorization|proxy-authorization)\s*[:=]\s*["']?basic\s+([A-Za-z0-9+/]{16,}={0,2})'''
secretGroup = 1
entropy = 3
keywords = ["authorization", "basic"]
tags = ["picket", "strict", "http", "basic-auth"]
severity = "critical"
confidence = "medium"
rulePack = "picket-strict"
provider = "HTTP"
documentationUrl = "https://www.rfc-editor.org/rfc/rfc7617"
examples = ["Authorization: Basic {{basicAuthorization}}"]
negativeExamples = [
    "Authorization: Bearer opaque-token-value",
    "Authorization: Basic {{basicAuthorizationPlaceholder}}",
]

[[rules.allowlists]]
regexTarget = "secret"
regexes = ['''^{{basicAuthorizationPlaceholder}}$''']

[[rules]]
id = "picket-strict-azure-sas-signature"
description = "Detected a signature in an Azure shared access signature query string."
regex = '''(?i)(?:[?&](?:sv|se|sp|sr)=[^&\s'"\x60]{1,256}){2,8}&sig=([A-Za-z0-9%+/]{20,}(?:%3D|=){0,2})'''
secretGroup = 1
entropy = 3
keywords = ["sig=", "sv="]
tags = ["picket", "strict", "azure", "sas", "signature"]
severity = "critical"
confidence = "medium"
rulePack = "picket-strict"
provider = "Azure"
documentationUrl = "https://learn.microsoft.com/azure/storage/common/storage-sas-overview"
examples = ["https://storage.example.invalid/container/blob?sv=2025-01-05&sp=r&se=2030-01-01T00%3A00%3A00Z&sr=b&sig={{sasSignature}}"]
negativeExamples = ["https://example.invalid/download?sig={{sasSignature}}"]
""";
    }

    private static string CreateExample(params string[] parts)
    {
        return string.Concat(parts);
    }
}
