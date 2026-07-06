namespace Picket.Compat;

internal static class EmbeddedPicketConfig
{
    internal const string SourceVersion = "picket-2026-07-06";

    internal const string Toml = """
title = "picket native default config"

[extend]
useDefault = true
disabledRules = [
    "github-app-token",
    "github-fine-grained-pat",
    "github-oauth",
    "github-pat",
    "github-refresh-token",
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
""";
}
