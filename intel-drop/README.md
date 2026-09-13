# Intelligence drop directory

File-drop threat-intelligence feeds read from here (`THREAT_INTEL_DROP_DIR`).
This is how intelligence reaches an air-gapped deployment, and how a
subscription whose licence forbids automated pulling gets loaded.

A feed is configured with a `filename` relative to this directory; the
filename is treated as untrusted and cannot escape it. Supported formats are
`plain` (one indicator per line, `#` comments), `csv` and `json`.

Nothing in here is committed except this file — indicator files are
operational data, may be licensed, and do not belong in the repository.
