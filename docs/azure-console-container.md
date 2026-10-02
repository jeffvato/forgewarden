# Retired Azure Container Apps console design

This document preserves the former packaging design for local reference only.
The hosted Azure console, `fw-vuln-job`, and their Azure resources are retired
and unavailable; no current repository workflow builds or deploys them. The
remaining console and vulnerability-image Dockerfiles are local, non-deployed
artifacts. Microsoft Foundry is not an active hosting or execution target.

## Local validation

Build and run the image locally before any Azure action:

```bash
docker build -f Dockerfile.console -t forgewarden-console:local \
  --label org.opencontainers.image.revision="$(git rev-parse HEAD)" .
docker run --rm --publish 8787:8787 forgewarden-console:local
curl --fail http://127.0.0.1:8787/api/status
```

The console remains plan-only and deployment-disabled inside the image. The
container listens on port `8787`; `/api/status` is the bounded health check.

## Historical Azure deployment shape — inactive

The former design considered a dedicated Container App in `fw-vuln-env`,
separate from `fw-vuln-job`. Neither resource is an active or approved target.
This historical description is not a deployment plan or evidence that those
resources still exist.

No mutation command is included. Restoring Azure hosting would require a new,
explicitly authorized design and review covering cost, identity, image digest,
ingress/authentication policy, observation, and rollback. Local image
validation does not authorize publishing, hosting, or deployment.
