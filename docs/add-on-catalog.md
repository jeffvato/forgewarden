# Local add-on catalog

Forgewarden can build a local catalog from explicitly supplied package
directories. Admission requires a valid manifest, matching digest, safe
entrypoint, and an explicitly allowlisted publisher. Catalog generation does
not fetch, install, or execute packages.

Remote catalogs and public-key signature verification remain separate release
gates. Until those are implemented and reviewed, the local catalog is the
only supported admission path.
