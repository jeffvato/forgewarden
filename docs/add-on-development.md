# Forgewarden add-on development

Forgewarden add-ons begin as declarative, signed manifests. The manifest
declares identity, version, entrypoint, capabilities, and permissions before
any UI or task integration is admitted.

Allowed capabilities are currently `ui.panel`, `task.plan`, and
`evidence.read`. Add-ons cannot request shell, Git, network, production, or
credential access. Task add-ons must explicitly declare `job_status` read
access. All entrypoints are relative paths with traversal and symlink checks.

The local lifecycle manager supports install, enable, disable, update, explicit
rollback, and confirmation-gated removal. Updates are version-increasing,
retain the prior package under a managed backup root, and disable the updated
record until a human enables it. The console exposes registry posture without
executing add-on code.

The signature field currently validates a canonical SHA-256 digest and key
identifier. Public-key signature verification and catalog admission remain
required before any remote or customer distribution path is enabled. Add-ons
are still local files only and are never executed by the lifecycle manager.
