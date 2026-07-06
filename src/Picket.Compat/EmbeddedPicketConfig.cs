namespace Picket.Compat;

internal static class EmbeddedPicketConfig
{
    internal const string SourceVersion = "picket-2026-07-06";

    internal static string Toml { get; } = CreateToml();

    private static string CreateToml()
    {
        string awsAccessKeyId = CreateExample("A3T0", "EXAMPLEEXAMPLE22");
        string awsSecretAccessKey = CreateExample("Tg0pz8Jii8hkLx4+", "PnUisM8GmKs3a2", "DK+9qz/lie");
        string azureStorageAccountKey = CreateExample(
            "MDEyMzQ1Njc4OUFCQ0RFRkdISktMTU5PUFFS",
            "U1RVVldYWVoxMjM0NTY3ODlBQkNERUZHSElK",
            "S0xNTk9QUVJTVA==");
        string googleApiKey = CreateExample("AIza", "SyDabcdefghijklmnopqrstuvwxyz123456");
        string gcpServiceAccountExample = CreateExample(
            "{\"type\":\"",
            "service_account",
            "\",\"client_email\":\"scanner-sa@picket-prod-123.iam.gserviceaccount.com\"}");
        string gcpServiceAccountNegativeExample = "{\"type\":\"user\",\"project_id\":\"picket-prod-123\"}";
        string sourcegraphAccessToken = CreateExample("sgp_", "0123456789abcdef0123456789abcdef01234567");
        string githubClassicTokenSuffix = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string githubFineGrainedToken = CreateExample(
            "github",
            "_pat_",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789");

        return $$"""
title = "picket native default config"

[extend]
useDefault = true
disabledRules = [
    "github-app-token",
    "github-fine-grained-pat",
    "github-oauth",
    "github-pat",
    "github-refresh-token",
    "sourcegraph-access-token",
]

[[rules]]
id = "picket-aws-access-key-pair"
description = "Detected an AWS access key ID paired with a secret access key."
regex = '''(?i)(?:aws[_ -]?access[_ -]?key[_ -]?id|secret[_ -]?access[_ -]?key)'''
entropy = 4.25
keywords = ["akia", "asia", "abia", "acca", "a3t", "aws_secret_access_key", "secret_access_key", "SecretAccessKey"]
tags = ["picket", "aws", "access-key", "secret-access-key"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "AWS"
documentationUrl = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
validation = ["offline:aws-access-key-pair"]
revocation = ["revocation:aws-iam-access-key"]
examples = ["aws_access_key_id = {{awsAccessKeyId}}\naws_secret_access_key = {{awsSecretAccessKey}}"]
negativeExamples = ["aws_access_key_id = {{awsAccessKeyId}}"]

[[rules]]
id = "picket-azure-storage-connection-string"
description = "Detected an Azure Storage connection string with an account key."
regex = '''(?i)\bDefaultEndpointsProtocol=https?;AccountName=([a-z0-9]{3,24});AccountKey=([A-Za-z0-9+/]{80,}={0,2})(?:;EndpointSuffix=[a-z0-9.-]+)?\b'''
secretGroup = 2
entropy = 4
keywords = ["AccountKey=", "DefaultEndpointsProtocol"]
tags = ["picket", "azure", "storage", "connection-string"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Azure"
documentationUrl = "https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage"
validation = ["offline:azure-storage-connection-string"]
revocation = ["revocation:azure-storage-account-key"]
examples = ["DefaultEndpointsProtocol=https;AccountName=picketstorage;AccountKey={{azureStorageAccountKey}};EndpointSuffix=core.windows.net"]
negativeExamples = ["DefaultEndpointsProtocol=https;AccountName=picketstorage;EndpointSuffix=core.windows.net"]

[[rules]]
id = "picket-google-api-key"
description = "Detected a Google API key."
regex = '''\b(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)'''
secretGroup = 1
keywords = ["aiza"]
tags = ["picket", "gcp", "google", "api-key"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "GCP"
documentationUrl = "https://cloud.google.com/docs/authentication/api-keys"
validation = ["offline:gcp-api-key"]
revocation = ["revocation:gcp-api-key"]
examples = ["api_key = \"{{googleApiKey}}\""]
negativeExamples = ["api_key = \"AIza-not-long-enough\""]

[[rules]]
id = "picket-gcp-service-account-key"
description = "Detected a Google Cloud service account key JSON document."
regex = '''"type"\s*:\s*"service_account"'''
keywords = ["service_account", "private_key_id", "iam.gserviceaccount.com"]
tags = ["picket", "gcp", "google", "service-account", "json"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "GCP"
documentationUrl = "https://cloud.google.com/iam/docs/keys-create-delete"
validation = ["offline:gcp-service-account-key-json"]
revocation = ["revocation:gcp-service-account-key"]
examples = ['''{{gcpServiceAccountExample}}''']
negativeExamples = ['''{{gcpServiceAccountNegativeExample}}''']

[[rules]]
id = "picket-sourcegraph-access-token"
description = "Detected a Sourcegraph access token."
regex = '''(?i)\b(sgp_(?:[a-f0-9]{16}|local)_[a-f0-9]{40}|sgp_[a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)'''
secretGroup = 1
entropy = 3
keywords = ["sgp_"]
tags = ["picket", "sourcegraph", "access-token"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Sourcegraph"
documentationUrl = "https://sourcegraph.com/docs/api"
examples = ["{{sourcegraphAccessToken}}"]
negativeExamples = ["4c232b5014f7618360bd992b4c489cb055881c6b"]

[[rules]]
id = "picket-github-app-token"
description = "Detected a GitHub App user or server token."
regex = '''\b((?:ghu|ghs)_[0-9A-Za-z]{36})\b'''
secretGroup = 1
entropy = 3
keywords = ["ghu_", "ghs_"]
tags = ["picket", "github", "github-app", "token"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "GitHub"
documentationUrl = "https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app"
validation = ["offline:github-classic-token", "live:github-rest-user-v1"]
revocation = ["revocation:github-credentials-api"]
examples = ["ghs_{{githubClassicTokenSuffix}}"]
negativeExamples = ["ghs_invalid"]

[[rules]]
id = "picket-github-fine-grained-personal-access-token"
description = "Detected a GitHub fine-grained personal access token."
regex = '''\b(github_pat_[0-9A-Za-z_]{82})\b'''
secretGroup = 1
entropy = 3
keywords = ["github_pat_"]
tags = ["picket", "github", "personal-access-token", "fine-grained"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "GitHub"
documentationUrl = "https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
validation = ["offline:github-fine-grained-pat", "live:github-rest-user-v1"]
revocation = ["revocation:github-credentials-api"]
examples = ["{{githubFineGrainedToken}}"]
negativeExamples = ["github_pat_invalid"]

[[rules]]
id = "picket-github-oauth-token"
description = "Detected a GitHub OAuth access token."
regex = '''\b(gho_[0-9A-Za-z]{36})\b'''
secretGroup = 1
entropy = 3
keywords = ["gho_"]
tags = ["picket", "github", "oauth", "token"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "GitHub"
documentationUrl = "https://docs.github.com/apps/oauth-apps/maintaining-oauth-apps/authorizing-oauth-apps"
validation = ["offline:github-classic-token", "live:github-rest-user-v1"]
revocation = ["revocation:github-credentials-api"]
examples = ["gho_{{githubClassicTokenSuffix}}"]
negativeExamples = ["gho_invalid"]

[[rules]]
id = "picket-github-personal-access-token"
description = "Detected a GitHub personal access token."
regex = '''\b(ghp_[0-9A-Za-z]{36})\b'''
secretGroup = 1
entropy = 3
keywords = ["ghp_"]
tags = ["picket", "github", "personal-access-token"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "GitHub"
documentationUrl = "https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
validation = ["offline:github-classic-token", "live:github-rest-user-v1"]
revocation = ["revocation:github-credentials-api"]
examples = ["ghp_{{githubClassicTokenSuffix}}"]
negativeExamples = ["ghp_invalid"]

[[rules]]
id = "picket-github-refresh-token"
description = "Detected a GitHub refresh token."
regex = '''\b(ghr_[0-9A-Za-z]{36})\b'''
secretGroup = 1
entropy = 3
keywords = ["ghr_"]
tags = ["picket", "github", "refresh-token"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "GitHub"
documentationUrl = "https://docs.github.com/apps/oauth-apps/building-oauth-apps/refreshing-user-to-server-access-tokens"
validation = ["offline:github-classic-token", "live:github-rest-user-v1"]
revocation = ["revocation:github-credentials-api"]
examples = ["ghr_{{githubClassicTokenSuffix}}"]
negativeExamples = ["ghr_invalid"]
""";
    }

    private static string CreateExample(params string[] parts)
    {
        return string.Concat(parts);
    }
}
