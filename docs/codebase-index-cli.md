# Audited codebase index CLI

The index is a local, read-only evidence aid. It does not authorize admission,
mutation, deployment, or model access. Build it only from an approved isolated
checkout, and store the index outside that checkout.

Build an index for an opaque source revision:

```bash
PYTHONPATH=. python3 -m swarm.cli codebase-index-build \
  --repository /path/to/approved-checkout \
  --index-path /tmp/forgewarden-index.json \
  --revision <commit-or-snapshot-id>
```

Query it with an auditable actor and a bounded result count:

```bash
PYTHONPATH=. python3 -m swarm.cli codebase-index-query \
  --repository /path/to/approved-checkout \
  --index-path /tmp/forgewarden-index.json \
  --revision <commit-or-snapshot-id> \
  --term authentication \
  --actor pr-reviewer \
  --limit 20
```

Queries fail closed on a stale or malformed index by defaulting to a fresh
filesystem scan. Add `--no-fresh-scan` when stale data must be rejected rather
than refreshed.

Delete an index only with an auditable actor:

```bash
PYTHONPATH=. python3 -m swarm.cli codebase-index-delete \
  --repository /path/to/approved-checkout \
  --index-path /tmp/forgewarden-index.json \
  --revision <commit-or-snapshot-id> \
  --actor maintenance
```

Create a separate evidence artifact that confirms which files cited by a
quality-review report are present in the indexed revision:

```bash
PYTHONPATH=. python3 -m swarm.cli index-evidence \
  --quality-report /tmp/quality-review.json \
  --repository /path/to/approved-checkout \
  --index-path /tmp/forgewarden-index.json \
  --revision <commit-or-snapshot-id> \
  --actor pr-reviewer \
  --output /tmp/index-evidence.json
```

This artifact contains paths and revision metadata only. It does not copy
source content into the review result and does not change the quality gate.

Sensitive filenames, symlinks, path traversal, oversized/binary files, and
recognized secret patterns are excluded by the index contract. Index storage
is written with restrictive permissions and atomic replacement.
