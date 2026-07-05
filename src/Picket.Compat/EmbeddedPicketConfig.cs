namespace Picket.Compat;

internal static class EmbeddedPicketConfig
{
    internal const string SourceVersion = "picket-2026-07-05";

    internal const string Toml = """
title = "picket native default config"

[extend]
useDefault = true

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
""";
}
