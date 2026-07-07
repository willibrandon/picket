# Container Archives

Picket native scans can read local Docker and OCI image archives without contacting a registry.

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

Only one native source provider can be selected for a scan. Do not combine `--docker-archive` or `--oci-archive` with GitHub, GitLab, or Azure DevOps source enumeration flags.

Registry pulls and remote image references are separate planned source providers. They need credential handling, endpoint policy, redirect policy, and provenance rules before they become part of the scanner contract.
