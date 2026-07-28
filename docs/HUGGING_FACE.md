# Hugging Face

Picket can scan Hugging Face model repositories, dataset repositories, Spaces, storage buckets, discussions, and pull requests through native source enumeration for `picket scan`.

Set a read-only or fine-grained Hugging Face user access token in an environment variable. Picket accepts the variable name and never places the token value in command arguments.

```powershell
$env:HF_TOKEN = "<read-only-token>"
picket scan --huggingface-model owner/model --huggingface-token-env HF_TOKEN --report-format jsonl
```

Exactly one resource selector is required:

| Resource | Selector | Behavior |
| --- | --- | --- |
| Model | `--huggingface-model owner/name` | Scans a model repository. |
| Dataset | `--huggingface-dataset owner/name` | Scans a dataset repository. |
| Space | `--huggingface-space owner/name` | Scans a Space repository. |
| Bucket | `--huggingface-bucket owner/name` | Scans a non-versioned storage bucket. |

## Repositories

Repository scans use `main` when `--huggingface-ref` is omitted. Picket resolves the selected branch, tag, or commit to an immutable commit SHA before listing and downloading files. Report paths and provenance retain that SHA.

```powershell
picket scan --huggingface-dataset owner/dataset --huggingface-ref v2 --huggingface-token-env HF_TOKEN --report-format jsonl
```

Pull request scans resolve Hugging Face's `refs/pr/<number>` revision and include the selected pull request's title, description, and comments as synthetic Markdown:

```powershell
picket scan --huggingface-space owner/space --huggingface-pull-request 42 --huggingface-token-env HF_TOKEN --report-format jsonl
```

`--huggingface-ref` and `--huggingface-pull-request` are mutually exclusive.

Discussion scanning is additive for model, dataset, and Space repositories:

```powershell
picket scan --huggingface-model owner/model --huggingface-include-discussions --huggingface-token-env HF_TOKEN --report-format jsonl
```

Picket lists repository discussions and scans their titles, descriptions, and comments as synthetic Markdown. Pull requests remain explicit through `--huggingface-pull-request`.

## Buckets

Hugging Face storage buckets are mutable and do not have revisions or pull requests. Picket identifies each downloaded object with its returned Xet content hash when available. A prefix narrows enumeration:

```powershell
picket scan --huggingface-bucket owner/checkpoints --huggingface-bucket-prefix releases/ --huggingface-token-env HF_TOKEN --report-format jsonl
```

Bucket scans reject repository revisions, pull requests, and discussion enumeration.

## Options

| Option | Purpose |
| --- | --- |
| `--huggingface-model` | Model repository name or `namespace/name`. |
| `--huggingface-dataset` | Dataset repository name or `namespace/name`. |
| `--huggingface-space` | Space repository name or `namespace/name`. |
| `--huggingface-bucket` | Storage bucket `namespace/name`. |
| `--huggingface-ref` | Optional repository branch, tag, or commit. Defaults to `main`. |
| `--huggingface-pull-request` | Optional positive pull request number. |
| `--huggingface-include-discussions` | Include repository discussion text and comments. |
| `--huggingface-bucket-prefix` | Limit a bucket scan to an object path prefix. |
| `--huggingface-token-env` | Environment variable containing the Hugging Face token. |
| `--huggingface-endpoint` | Hub endpoint. Defaults to `https://huggingface.co/`. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses. |
| `--allow-insecure-source-endpoints` | Permit HTTP and cleartext credential transport for an explicitly trusted endpoint. |

## Limits And Safety

Provider metadata JSON is capped at 10 decimal MB. Repository trees, bucket trees, and discussion lists stop at 1,000 pages and warn when the limit is reached. Remote file downloads use a 100 decimal MB default cap; a positive `--max-target-megabytes` overrides it. Size limits are enforced while streaming even when `Content-Length` is absent or understated.

Supported archives use Picket's `--max-archive-depth`, `--max-archive-entries`, `--max-archive-megabytes`, and `--max-archive-ratio` limits. Archive entries also obey `--max-target-megabytes`.

Endpoint safety checks run before the first request and again at connection time. HTTPS is required by default. Automatic redirects are rejected. Picket follows at most one allowed HTTPS file-download redirect and does not forward the bearer token; a second redirect is rejected.

Repository tree and bucket tree pagination links must remain on the configured endpoint. Public Hub downloads may redirect to Hugging Face content hosts. Custom endpoints may redirect only to their own host or a subdomain.

## Permissions

Use a read-only token or a fine-grained token restricted to the selected private or gated resources. Picket requires a named token environment variable for both public and private Hugging Face sources. Write, repository administration, organization administration, and token administration permissions are not required.

## References

- Hub API endpoints: `https://huggingface.co/docs/hub/api`
- Hub repositories: `https://huggingface.co/docs/hub/repositories`
- Pull requests and discussions: `https://huggingface.co/docs/hub/repositories-pull-requests-discussions`
- Storage buckets: `https://huggingface.co/docs/hub/storage-buckets`
- User access tokens: `https://huggingface.co/docs/hub/security-tokens`
