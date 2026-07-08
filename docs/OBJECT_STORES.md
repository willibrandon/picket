# Object Stores

Picket can scan Azure Blob Storage containers through native source enumeration for `picket scan`.

This is opt-in native source behavior. Workspace scans remain the default, and strict Gitleaks-compatible commands are unchanged.

```powershell
picket scan --azure-blob-endpoint https://account.blob.core.windows.net/ --azure-blob-container secrets --azure-blob-token-env PICKET_AZURE_BLOB_TOKEN --report-format jsonl
```

Blob names can be filtered by prefix:

```powershell
picket scan --azure-blob-endpoint https://account.blob.core.windows.net/ --azure-blob-container secrets --azure-blob-prefix prod/ --azure-blob-token-env PICKET_AZURE_BLOB_TOKEN --report-format jsonl
```

The token is read from an environment variable and is never passed as a command-line value.

Bearer tokens are the default credential kind. Shared access signatures are supported when the SAS string is stored in an environment variable:

```powershell
picket scan --azure-blob-endpoint https://account.blob.core.windows.net/ --azure-blob-container secrets --azure-blob-token-env PICKET_AZURE_BLOB_SAS --azure-blob-token-kind sas --report-format jsonl
```

| Option | Purpose |
| --- | --- |
| `--azure-blob-endpoint` | Blob service endpoint, such as `https://account.blob.core.windows.net/`. |
| `--azure-blob-container` | Container to enumerate. |
| `--azure-blob-prefix` | Optional blob name prefix. |
| `--azure-blob-token-env` | Environment variable containing a bearer token or shared access signature. |
| `--azure-blob-token-kind` | Credential kind: `bearer` or `sas`. Defaults to `bearer`. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoints for explicitly trusted storage endpoints. |
| `--allow-insecure-source-endpoints` | Permit HTTP source endpoints for trusted local tests or explicitly accepted private environments. |

## API Flow

| Source | API behavior |
| --- | --- |
| Blob listing | Lists blobs with `restype=container`, `comp=list`, `maxresults=5000`, and an optional `prefix`. |
| Pagination | Follows `NextMarker` while present and stops at a 1,000-page safety limit with a warning. |
| Blob content | Downloads selected blob bytes through `Get Blob`. |

## Limits

Remote downloads use a 100 decimal MB default cap. `--max-target-megabytes` overrides that cap with a positive value. Zero keeps its local-scan compatibility meaning, but remote Azure Blob sources reject zero because remote HTTP bodies are always bounded.

Provider metadata XML responses are separately capped at 10 decimal MB and skipped with a warning when the cap is exceeded, including responses without a reliable `Content-Length`.

Oversized blobs are skipped before download when Azure Blob Storage returns a `Content-Length` in the listing. Responses without a reliable length are still capped during streaming.

## Redirect And Credential Safety

Endpoint safety checks run before the first request.

Redirects are disabled before credentials are sent, and responses from injected HTTP handlers that already followed a redirect are rejected instead of scanned.

Bearer credentials are sent in the `Authorization` header. Shared access signatures are appended to Azure Blob Storage request query strings because that is the provider contract. Picket reads them from environment variables and does not print them in diagnostics.

## Permissions

Use the narrowest container and prefix selection possible. Bearer-token scans need read-only data-plane permission to list blobs in the selected container and read selected blob content. SAS scans need list and read permissions for the selected container or blob scope. Write, delete, lease, tag mutation, account management, and key-management permissions are not needed for source enumeration.

S3 and GCS remain planned object-store providers. They should follow the same source-provider shape: environment-sourced credentials, endpoint guard, explicit pagination caps, per-object byte caps, redirect safety, and provider-specific permission guidance.

## References

- Azure Blob Storage REST API: `https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api`
- List Blobs REST API: `https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs`
- Get Blob REST API: `https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob`
- Azure Storage service versioning: `https://learn.microsoft.com/en-us/rest/api/storageservices/versioning-for-the-azure-storage-services`
