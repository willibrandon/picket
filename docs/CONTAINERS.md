# Container Archives

Picket native scans can read local Docker and OCI image archives without contacting a registry.

## Scanner Image

Release tags publish a Linux scanner image to GHCR:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/willibrandon/picket:latest scan . --report-format jsonl --redact=100
```

The image runs `picket` by default from `/work`, includes `picket-tui` for companion terminal triage, includes `git` for `picket git`, and runs as a non-root user. Override the user only when a mounted workspace requires it.

For reproducible releases, prefer an immutable version tag such as `ghcr.io/willibrandon/picket:v0.4.2` or `ghcr.io/willibrandon/picket:0.4.2` instead of `latest`.

Build the image locally with Docker:

```powershell
docker build -t picket:dev .
docker run --rm -v ${PWD}:/work picket:dev scan . --report-format jsonl --redact=100
```

On Windows with the WSL container CLI:

```powershell
wslc image build -t picket:dev .
wslc run --rm -v ${PWD}:/work picket:dev scan . --report-format jsonl --redact=100
```

## Image Archive Scanning

Use `--docker-archive` for archives produced by `docker save`:

```bash
picket scan --docker-archive image.tar --report-format jsonl --redact=100
```

Use `--oci-archive` for OCI image-layout archives:

```bash
picket scan --oci-archive image-oci.tar --report-format jsonl --redact=100
```

Container archive scanning is native Picket behavior. It is not part of the Gitleaks-compatible `git`, `dir`, or `stdin` surfaces.

The scanner treats the image archive as a source envelope. It scans metadata files such as manifests and configs, expands layer tarballs or gzip-compressed layer blobs, and reports paths with container provenance:

```text
docker-archive/image.tar!layer/layer.tar!app/settings.txt
oci-archive/image-oci.tar!blobs/sha256/<digest>!etc/secret.conf
```

The normal archive safety controls apply:

| Option | Behavior |
|---|---|
| `--max-archive-depth` | Limits nested archive traversal inside the image envelope. |
| `--max-archive-entries` | Caps extracted entries. |
| `--max-archive-megabytes` | Caps decompressed archive bytes. |
| `--max-archive-ratio` | Caps archive expansion ratio. |
| `--max-target-megabytes` | Skips oversized yielded files. |
| `--timeout` | Stops long scans between scanner work units. |

Only one native source provider can be selected for a scan. Do not combine `--docker-archive` or `--oci-archive` with GitHub, Gitea, GitLab, Bitbucket, Azure DevOps, or object-store source enumeration flags.

Registry pulls and remote image references are separate planned source providers. They need credential handling, endpoint policy, redirect policy, and provenance rules before they become part of the scanner contract.
