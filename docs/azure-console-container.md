# Azure Container Apps console packaging

This package hosts the Forgewarden read-only management console as a dedicated
Azure Container App. It is separate from the `fw-vuln-job` Container Apps Job,
which is a scheduled vulnerability-intelligence worker, and separate from
Microsoft Foundry, which supplies optional AI resources rather than web hosting.

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

## Azure deployment shape — preparation only

Microsoft documents `az containerapp up` for deploying a Python web app from
local source or an existing image. The eventual target should be a new named
Container App in the existing `fw-vuln-env`, for example
`forgewarden-console-dev`; it must not update `fw-vuln-job`.

The exact mutation command is intentionally not included until the app name,
image digest, ingress/authentication policy, health/observation window, and
rollback revision are separately approved. Foundry resources are optional
backend dependencies and must not be used as the console hosting target.
