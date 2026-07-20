namespace Picket.Compat;

internal static class EmbeddedPicketConfig
{
    internal const string SourceVersion = "picket-2026-07-19";

    internal static string Toml { get; } = CreateToml();

    private static string CreateToml()
    {
        string anthropicOAuthAccessToken = CreateExample("sk-ant-oat01-", CreateExampleBody(95));
        string anthropicOAuthRefreshToken = CreateExample("sk-ant-ort01-", CreateExampleBody(95));
        string awsAccessKeyId = CreateExample("A3T0", "EXAMPLEEXAMPLE22");
        string awsSecretAccessKey = CreateExample("Tg0pz8Jii8hkLx4+", "PnUisM8GmKs3a2", "DK+9qz/lie");
        string azureStorageAccountKey = CreateExample(
            "MDEyMzQ1Njc4OUFCQ0RFRkdISktMTU5PUFFS",
            "U1RVVldYWVoxMjM0NTY3ODlBQkNERUZHSElK",
            "S0xNTk9QUVJTVA==");
        string claudeCodeSessionUrl = CreateExample(
            "https://claude.ai/code/session_",
            CreateAlphaNumericExampleBody(24));
        string codexAccessToken = CreateExample(
            "eyJ",
            CreateExampleBody(29),
            ".eyJ",
            CreateExampleBody(77),
            ".",
            CreateExampleBody(64));
        string codexRefreshToken = CreateExample("rt_", CreateExampleBody(61));
        string codexAccessTokenExample = CreateExample(
            "{\"tokens\":{\"access_token\":\"",
            codexAccessToken,
            "\"}}");
        string codexRefreshTokenExample = CreateExample(
            "{\"tokens\":{\"refresh_token\":\"",
            codexRefreshToken,
            "\"}}");
        string dockerCredential = Convert.ToBase64String("picket-user:picket-password"u8);
        string dockerCredentialExample = CreateExample(
            "{\"auths\":{\"registry.example.com\":{\"auth\":\"",
            dockerCredential,
            "\"}}}");
        string dockerCredentialNegativeExample = CreateExample(
            "{\"settings\":{\"auth\":\"",
            dockerCredential,
            "\"}}");
        string googleApiKey = CreateExample("AIza", "SyDabcdefghijklmnopqrstuvwxyz123456");
        string groqApiKey = CreateExample("gsk_", CreateAlphaNumericExampleBody(48));
        string gcpPrivateKey = CreateExample(
            "-----BEGIN PRIVATE KEY-----\\n",
            CreateExampleBody(64),
            "\\n-----END PRIVATE KEY-----\\n");
        string gcpServiceAccountExample = CreateExample(
            "{\"type\":\"",
            "service_account",
            "\",\"client_email\":\"scanner-sa@picket-prod-123.iam.gserviceaccount.com\",\"private_key\":\"",
            gcpPrivateKey,
            "\"}");
        string gcpServiceAccountNegativeExample = "{\"type\":\"user\",\"project_id\":\"picket-prod-123\"}";
        string sourcegraphAccessToken = CreateExample("sgp_", "0123456789abcdef0123456789abcdef01234567");
        string databaseConnectionUrl = CreateExample(
            "postgresql://app_user:",
            "picket-db-password-123",
            "@db.internal.local:5432/appdb?sslmode=require");
        string githubClassicTokenSuffix = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        string githubInstallationToken = CreateExample(
            "ghs_123456_",
            CreateExampleBody(32),
            ".",
            CreateExampleBody(256),
            ".",
            CreateExampleBody(128));
        string githubFineGrainedToken = CreateExample(
            "github",
            "_pat_",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789");
        string jwkPrivateParameter = CreateExampleBody(48);
        string jwkPrivateExample = CreateExample(
            "{\"kty\":\"RSA\",\"n\":\"",
            jwkPrivateParameter,
            "\",\"e\":\"AQAB\",\"d\":\"",
            jwkPrivateParameter,
            "\"}");
        string jwkPublicExample = CreateExample(
            "{\"kty\":\"RSA\",\"n\":\"",
            jwkPrivateParameter,
            "\",\"e\":\"AQAB\"}");
        string kubernetesSecret = Convert.ToBase64String("picket-kubernetes-password"u8);
        string mcpServerCredential = CreateExample(
            "mcp_",
            "a8F2kL9mQ4xT7vN1zR6pW3cY",
            "5uH0jK8sD2qP9bX4nM7wE1tL");
        string mcpServerCredentialExample = CreateExample(
            "{\"mcpServers\":{\"linear\":{\"command\":\"npx\",\"env\":{\"LINEAR_API_KEY\":\"",
            mcpServerCredential,
            "\",\"LOG_LEVEL\":\"debug\"}}}}");
        string mcpServerEnvironmentReference =
            "{\"mcpServers\":{\"linear\":{\"env\":{\"LINEAR_API_KEY\":\"${LINEAR_API_KEY}\"}}}}";
        string mcpServerOutsideEnvironment = CreateExample(
            "{\"env\":{\"LINEAR_API_KEY\":\"",
            mcpServerCredential,
            "\"}}");
        string npmBasicCredential = Convert.ToBase64String("picket-user:picket-password"u8);
        string npmPassword = Convert.ToBase64String("picket-password"u8);
        string npmToken = CreateExample("npm_", CreateExampleBody(36));
        string openAiApiKey = CreateExample("sk-proj-", CreateExampleBody(96));
        string xAiApiKey = CreateExample("xai-", CreateAlphaNumericExampleBody(80));

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
    "kubernetes-secret-yaml",
    "openai-api-key",
    "sourcegraph-access-token",
]

[[rules]]
id = "generic-api-key"
regex = '''(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token|pword|pw|seckey|tkn|signature|sign|sgn)(?:[ \t\w.-]{0,40})(?:[ \t]*:[ \t]*(?:str|SecretStr))?[ \t'" ]{0,100}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)(?:[ \t]*(?:\\[ \t]*\r?\n)?[\x60'"\s=(]{0,100})(?:(?:str|SecretStr)[ \t]*\([\x60'"\s]{0,100})?([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;)\]]|\\[nr]|$)'''
keywords = ["pword", "pw", "seckey", "tkn", "signature", "sign", "sgn"]
randomnessThreshold = 0.5
examples = [
    "secret                         = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"",
    "my_secret: SecretStr = SecretStr(\"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\")",
    "pword = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"",
]
negativeExamples = [
    "<my-custom-component v-model=\"anyValWithKeyInside\" :followed-by-a-dynamic-attributes-with-at-least-two-dashes=\"true\" />",
]

[[rules]]
id = "square-access-token"
randomnessThreshold = 0.6

[[rules]]
id = "picket-anthropic-oauth-access-token"
description = "Detected an Anthropic OAuth access token."
regex = '''\b(sk-ant-oat01-[A-Za-z0-9_-]{95})(?:[\x60'"\s;,&?#]|\\[nr]|$)'''
secretGroup = 1
keywords = ["sk-ant-oat01-"]
tags = ["picket", "anthropic", "claude", "oauth", "access-token"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Anthropic"
documentationUrl = "https://code.claude.com/docs/en/authentication"
validation = ["offline:anthropic-oauth-token"]
examples = ["CLAUDE_CODE_OAUTH_TOKEN={{anthropicOAuthAccessToken}}"]
negativeExamples = ["CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-too-short"]

[[rules]]
id = "picket-anthropic-oauth-refresh-token"
description = "Detected an Anthropic OAuth refresh token."
regex = '''\b(sk-ant-ort01-[A-Za-z0-9_-]{95})(?:[\x60'"\s;,&?#]|\\[nr]|$)'''
secretGroup = 1
keywords = ["sk-ant-ort01-"]
tags = ["picket", "anthropic", "claude", "oauth", "refresh-token"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Anthropic"
documentationUrl = "https://code.claude.com/docs/en/authentication"
validation = ["offline:anthropic-oauth-token"]
examples = ["refresh_token = \"{{anthropicOAuthRefreshToken}}\""]
negativeExamples = ["refresh_token = \"sk-ant-ort01-too-short\""]

[[rules]]
id = "picket-claude-code-session-url"
description = "Detected a Claude Code Remote Control session URL."
regex = '''(?i)\b(https?://claude\.ai/code/session_[A-Za-z0-9]{16,128})\b'''
secretGroup = 1
keywords = ["claude.ai/code/session_"]
tags = ["picket", "anthropic", "claude-code", "remote-control", "session"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Anthropic"
documentationUrl = "https://code.claude.com/docs/en/remote-control"
validation = ["offline:claude-code-session-url"]
examples = ["remote_control = \"{{claudeCodeSessionUrl}}\""]
negativeExamples = ["https://example.com/code/session_0123456789abcdefghijklmn"]

[[rules]]
id = "picket-groq-api-key"
description = "Detected a Groq API key."
regex = '''\b(gsk_[A-Za-z0-9]{48})\b'''
secretGroup = 1
keywords = ["gsk_"]
tags = ["picket", "groq", "api-key"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Groq"
documentationUrl = "https://console.groq.com/docs/quickstart"
validation = ["offline:groq-api-key"]
examples = ["GROQ_API_KEY={{groqApiKey}}"]
negativeExamples = ["GROQ_API_KEY=gsk_too_short"]

[[rules]]
id = "picket-xai-api-key"
description = "Detected an xAI API key."
regex = '''\b(xai-[A-Za-z0-9]{80})\b'''
secretGroup = 1
keywords = ["xai-"]
tags = ["picket", "xai", "grok", "api-key"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "xAI"
documentationUrl = "https://docs.x.ai/docs/getting-started"
validation = ["offline:xai-api-key"]
examples = ["XAI_API_KEY={{xAiApiKey}}"]
negativeExamples = ["XAI_API_KEY=xai-too-short"]

[[rules]]
id = "picket-openai-api-key"
description = "Detected an OpenAI API key."
regex = '''\b(sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,512}|[A-Za-z0-9]{20,48}T3BlbkFJ[A-Za-z0-9]{20,48}))(?:[\x60'"\s;,&?#]|\\[nr]|$)'''
secretGroup = 1
keywords = ["sk-proj-", "sk-svcacct-", "sk-admin-", "T3BlbkFJ"]
tags = ["picket", "openai", "chatgpt", "api-key"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "OpenAI"
documentationUrl = "https://platform.openai.com/docs/api-reference/authentication"
validation = ["offline:openai-api-key"]
examples = ["OPENAI_API_KEY={{openAiApiKey}}"]
negativeExamples = ["OPENAI_API_KEY=sk-proj-placeholder"]

[[rules]]
id = "picket-openai-codex-access-token"
description = "Detected a Codex OAuth access token."
regex = '''(?i)\baccess_token\b'''
keywords = ["access_token"]
tags = ["picket", "openai", "codex", "oauth", "access-token", "structured"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "OpenAI"
documentationUrl = "https://developers.openai.com/codex/auth"
validation = ["offline:codex-access-token"]
detector = "codex-credentials"
examples = ['''{{codexAccessTokenExample}}''']
negativeExamples = ['''{"tokens":{"access_token":"not-a-jwt"} }''']

[[rules]]
id = "picket-openai-codex-refresh-token"
description = "Detected a Codex OAuth refresh token."
regex = '''(?i)\brefresh_token\b'''
keywords = ["refresh_token"]
tags = ["picket", "openai", "codex", "oauth", "refresh-token", "structured"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "OpenAI"
documentationUrl = "https://developers.openai.com/codex/auth"
validation = ["offline:codex-refresh-token"]
detector = "codex-credentials"
examples = ['''{{codexRefreshTokenExample}}''']
negativeExamples = ['''{"tokens":{"refresh_token":"too-short"} }''']

[[rules]]
id = "picket-docker-registry-auth"
description = "Detected Docker registry credentials in an auth configuration."
regex = '''(?i)"auths"[ \t\r\n]*:'''
keywords = ["auths"]
tags = ["picket", "docker", "registry", "basic-auth", "structured"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Docker"
documentationUrl = "https://docs.docker.com/reference/cli/docker/login/"
validation = ["offline:docker-registry-auth"]
detector = "docker-registry-credentials"
examples = ['''{{dockerCredentialExample}}''']
negativeExamples = ['''{{dockerCredentialNegativeExample}}''']

[[rules]]
id = "picket-jwk-private-key"
description = "Detected private key material in a JSON Web Key."
regex = '''(?i)"kty"[ \t\r\n]*:'''
keywords = ["kty"]
tags = ["picket", "jwk", "private-key", "structured"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "JWK"
documentationUrl = "https://www.rfc-editor.org/rfc/rfc7517"
validation = ["offline:jwk-private-key"]
detector = "jwk-private-key"
examples = ['''{{jwkPrivateExample}}''']
negativeExamples = ['''{{jwkPublicExample}}''']

[[rules]]
id = "picket-kubernetes-secret"
description = "Detected a value in a Kubernetes Secret resource."
regex = '''(?i)\bkind[ \t]*:[ \t]*Secret\b'''
keywords = ["kind", "secret"]
tags = ["picket", "kubernetes", "secret", "yaml", "structured"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Kubernetes"
documentationUrl = "https://kubernetes.io/docs/concepts/configuration/secret/"
validation = ["offline:kubernetes-secret"]
detector = "kubernetes-secret"
examples = ["apiVersion: v1\ndata:\n  password: {{kubernetesSecret}}\nkind: Secret"]
negativeExamples = ["apiVersion: v1\ndata:\n  setting: {{kubernetesSecret}}\nkind: ConfigMap"]

[[rules]]
id = "picket-mcp-server-credential"
description = "Detected a credential in a Model Context Protocol server configuration."
regex = '''(?i)"mcpServers"[ \t\r\n]*:'''
keywords = ["mcpServers"]
randomnessThreshold = 0.5
tags = ["picket", "mcp", "credential", "structured", "json"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "MCP"
documentationUrl = "https://modelcontextprotocol.io/docs/develop/connect-local-servers"
validation = ["offline:mcp-server-credential"]
detector = "mcp-server-credentials"
examples = ['''{{mcpServerCredentialExample}}''']
negativeExamples = ['''{{mcpServerEnvironmentReference}}''', '''{{mcpServerOutsideEnvironment}}''']

[[rules]]
id = "picket-npm-auth-token"
description = "Detected an npm authentication token in npm configuration."
regex = '''(?i)_authToken[ \t]*='''
keywords = ["_authtoken"]
tags = ["picket", "npm", "auth-token", "structured"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "npm"
documentationUrl = "https://docs.npmjs.com/cli/v11/configuring-npm/npmrc"
validation = ["offline:npm-auth-token"]
detector = "npm-credentials"
examples = ["//registry.npmjs.org/:_authToken={{npmToken}}"]
negativeExamples = ["//registry.npmjs.org/:_authToken=${NPM_TOKEN}"]

[[rules]]
id = "picket-npm-basic-auth"
description = "Detected npm basic authentication credentials in npm configuration."
regex = '''(?i)_(?:auth|password)[ \t]*='''
keywords = ["_auth", "_password"]
tags = ["picket", "npm", "basic-auth", "structured"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "npm"
documentationUrl = "https://docs.npmjs.com/cli/v11/configuring-npm/npmrc"
validation = ["offline:npm-basic-auth"]
detector = "npm-credentials"
examples = ["_auth={{npmBasicCredential}}", "username=picket-user\n_password={{npmPassword}}"]
negativeExamples = ["_auth=not-base64"]

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
regex = '''\b(AIza[\w-]{35})(?:[\x60'"\s;,&?#]|\\[nr]|$)'''
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
detector = "gcp-service-account-key"
examples = ['''{{gcpServiceAccountExample}}''']
negativeExamples = ['''{{gcpServiceAccountNegativeExample}}''']

[[rules]]
id = "picket-database-connection-url"
description = "Detected a database connection URL with embedded user credentials."
regex = '''(?i)\b((?:postgres(?:ql)?|mysql|mariadb|sqlserver|mongodb(?:\+srv)?|redis)://[^:/?#@\s'"\x60;]{1,128}:[^@\s'"\x60;]{8,256}@[^\s'"\x60<>;]{3,512})(?:[\x60'"\s;]|\\[nr]|$)'''
secretGroup = 1
entropy = 3.5
keywords = ["postgres://", "postgresql://", "mysql://", "mariadb://", "sqlserver://", "mongodb://", "mongodb+srv://", "redis://"]
tags = ["picket", "database", "connection-string", "connection-url"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "Database"
documentationUrl = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
validation = ["offline:database-connection-url"]
examples = ["{{databaseConnectionUrl}}"]
negativeExamples = ["postgresql://app_user@db.internal.local:5432/appdb"]

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
validation = ["offline:sourcegraph-access-token"]
examples = ["{{sourcegraphAccessToken}}"]
negativeExamples = ["4c232b5014f7618360bd992b4c489cb055881c6b"]

[[rules]]
id = "picket-github-app-token"
description = "Detected a GitHub App user or server token."
regex = '''\b(ghu_[0-9A-Za-z]{36}|ghs_(?:[0-9A-Za-z]{36}|[0-9]{1,20}_[A-Za-z0-9_-]{8,256}\.[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{8,1024}))(?:[\x60'"\s;,&?#]|\\[nr]|$)'''
secretGroup = 1
entropy = 3
keywords = ["ghu_", "ghs_"]
tags = ["picket", "github", "github-app", "token"]
severity = "critical"
confidence = "high"
rulePack = "picket-default"
provider = "GitHub"
documentationUrl = "https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app"
validation = ["offline:github-app-token", "live:github-rest-user-v1"]
revocation = ["revocation:github-credentials-api"]
examples = ["ghs_{{githubClassicTokenSuffix}}", "{{githubInstallationToken}}"]
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

    private static string CreateExampleBody(int length)
    {
        const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-";
        return string.Create(length, Alphabet, static (span, alphabet) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = alphabet[i % alphabet.Length];
            }
        });
    }

    private static string CreateAlphaNumericExampleBody(int length)
    {
        const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        return string.Create(length, Alphabet, static (span, alphabet) =>
        {
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = alphabet[i % alphabet.Length];
            }
        });
    }
}
