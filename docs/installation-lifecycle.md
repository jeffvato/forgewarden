# Forgewarden installation lifecycle

Forgewarden installation is being built around an ownership manifest. Every
installed file must be recorded with a release and SHA-256 digest under a
specific, non-broad installation root.

The manifest foundation supports safe previews for uninstall and retained
backup-based upgrade/rollback operations. It rejects home-directory or root installs,
path traversal, symlinked owned files, and manifests whose requested root does
not match the operation root.

The installer now stages an explicit release file list into a disposable
sibling directory, writes and validates the ownership manifest, and promotes
atomically while retaining the previous install under a managed backup root.
Rollback is explicit and restores a retained backup without deleting the
displaced current release. Use `packaging/forgewarden-install --help` for the
local lifecycle commands.

Uninstall remains preview-only by default and requires explicit confirmation
before removing only manifest-owned files. No installer command deploys,
restarts, or contacts production.
