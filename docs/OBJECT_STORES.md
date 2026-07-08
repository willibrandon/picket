# Object Stores

Picket can scan S3 buckets and Azure Blob Storage containers through native source enumeration for `picket scan`.

This is opt-in native source behavior. Workspace scans remain the default, and strict Gitleaks-compatible commands are unchanged.

```powershell
picket scan --azure-blob-endpoint https://account.blob.core.windows.net/ --azure-blob-container secrets --azure-blob-token-env PICKET_AZURE_BLOB_TOKEN --report-format jsonl
```

Blob names can be filtered by prefix:

```powershell
picket scan --azure-blob-endpoint https://account.blob.core.windows.net/ --azure-blob-container secrets --azure-blob-prefix prod/ --azure-blob-token-env PICKET_AZURE_BLOB_TOKEN --report-format jsonl
```

The token is read from an environment variable and is never passed as a command-line value.

## S3

S3 scans use SigV4-signed REST requests for `ListObjectsV2` and `GetObject`.

```powershell
picket scan --s3-bucket secrets --s3-region us-east-1 --s3-access-key-id-env PICKET_S3_ACCESS_KEY_ID --s3-secret-access-key-env PICKET_S3_SECRET_ACCESS_KEY --report-format jsonl
```

Object keys can be filtered by prefix:

```powershell
picket scan --s3-bucket secrets --s3-region us-east-1 --s3-prefix prod/ --s3-access-key-id-env PICKET_S3_ACCESS_KEY_ID --s3-secret-access-key-env PICKET_S3_SECRET_ACCESS_KEY --report-format jsonl
```

Temporary credentials can include a session token:

```powershell
picket scan --s3-bucket secrets --s3-region us-east-1 --s3-access-key-id-env PICKET_S3_ACCESS_KEY_ID --s3-secret-access-key-env PICKET_S3_SECRET_ACCESS_KEY --s3-session-token-env PICKET_S3_SESSION_TOKEN --report-format jsonl
```

S3-compatible endpoints can be selected explicitly:

```powershell
picket scan --s3-endpoint https://s3.example.internal/ --s3-bucket secrets --s3-region us-east-1 --s3-access-key-id-env PICKET_S3_ACCESS_KEY_ID --s3-secret-access-key-env PICKET_S3_SECRET_ACCESS_KEY --report-format jsonl
```

The access key ID, secret access key, and session token are read from environment variables and are never passed as command-line values.

| Option | Purpose |
| --- | --- |
| `--s3-bucket` | Bucket to enumerate. |
| `--s3-region` | AWS region used for SigV4 request signing. |
| `--s3-endpoint` | Optional S3 or S3-compatible endpoint. Defaults to the AWS regional S3 endpoint for `--s3-region`. |
| `--s3-prefix` | Optional object key prefix. |
| `--s3-access-key-id-env` | Environment variable containing the access key ID. |
| `--s3-secret-access-key-env` | Environment variable containing the secret access key. |
| `--s3-session-token-env` | Optional environment variable containing the session token for temporary credentials. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoints for explicitly trusted S3-compatible endpoints. |
| `--allow-insecure-source-endpoints` | Permit HTTP source endpoints for trusted local tests or explicitly accepted private environments. |

### S3 API Flow

| Source | API behavior |
| --- | --- |
| Object listing | Lists objects with `list-type=2`, `max-keys=1000`, and an optional `prefix`. |
| Pagination | Follows `NextContinuationToken` while present and stops at a 1,000-page safety limit with a warning. |
| Object content | Downloads selected object bytes through `GetObject`. |

Remote downloads use a 100 decimal MB default cap. `--max-target-megabytes` overrides that cap with a positive value. Zero keeps its local-scan compatibility meaning, but remote S3 sources reject zero because remote HTTP bodies are always bounded.

Provider metadata XML responses are separately capped at 10 decimal MB and skipped with a warning when the cap is exceeded, including responses without a reliable `Content-Length`.

Oversized objects are skipped before download when S3 returns a `Size` in the listing. Responses without a reliable length are still capped during streaming.

Endpoint safety checks run before the first request. Redirects are disabled before credentials are sent, and responses from injected HTTP handlers that already followed a redirect are rejected instead of scanned.

Bearer-style credentials are not used for S3. Picket signs requests with SigV4, sends the access key ID in the Authorization credential scope, and uses the secret access key only to compute the signature. Session tokens are sent in the `x-amz-security-token` header. Picket does not print the secret access key or session token in diagnostics.

Use the narrowest bucket and prefix selection possible. S3 scans need `s3:ListBucket` on the selected bucket and `s3:GetObject` on selected objects. Write, delete, tagging, ACL, bucket policy, replication, lifecycle, and key-management permissions are not needed for source enumeration.

## Azure Blob Storage

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

### Azure Blob API Flow

| Source | API behavior |
| --- | --- |
| Blob listing | Lists blobs with `restype=container`, `comp=list`, `maxresults=5000`, and an optional `prefix`. |
| Pagination | Follows `NextMarker` while present and stops at a 1,000-page safety limit with a warning. |
| Blob content | Downloads selected blob bytes through `Get Blob`. |

### Azure Blob Limits

Remote downloads use a 100 decimal MB default cap. `--max-target-megabytes` overrides that cap with a positive value. Zero keeps its local-scan compatibility meaning, but remote Azure Blob sources reject zero because remote HTTP bodies are always bounded.

Provider metadata XML responses are separately capped at 10 decimal MB and skipped with a warning when the cap is exceeded, including responses without a reliable `Content-Length`.

Oversized blobs are skipped before download when Azure Blob Storage returns a `Content-Length` in the listing. Responses without a reliable length are still capped during streaming.

### Azure Blob Redirect And Credential Safety

Endpoint safety checks run before the first request.

Redirects are disabled before credentials are sent, and responses from injected HTTP handlers that already followed a redirect are rejected instead of scanned.

Bearer credentials are sent in the `Authorization` header. Shared access signatures are appended to Azure Blob Storage request query strings because that is the provider contract. Picket reads them from environment variables and does not print them in diagnostics.

### Azure Blob Permissions

Use the narrowest container and prefix selection possible. Bearer-token scans need read-only data-plane permission to list blobs in the selected container and read selected blob content. SAS scans need list and read permissions for the selected container or blob scope. Write, delete, lease, tag mutation, account management, and key-management permissions are not needed for source enumeration.

GCS remains a planned object-store provider. It should follow the same source-provider shape: environment-sourced credentials, endpoint guard, explicit pagination caps, per-object byte caps, redirect safety, and provider-specific permission guidance.

## References

- Amazon S3 API Reference: `https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html`
- Amazon S3 ListObjectsV2 API: `https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html`
- Amazon S3 GetObject API: `https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html`
- AWS SigV4 signed requests: `https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html`
- Azure Blob Storage REST API: `https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api`
- List Blobs REST API: `https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs`
- Get Blob REST API: `https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob`
- Azure Storage service versioning: `https://learn.microsoft.com/en-us/rest/api/storageservices/versioning-for-the-azure-storage-services`
