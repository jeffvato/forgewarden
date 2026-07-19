# Windows Hermes Desktop connection

Status: **BLOCKED — no supported local Hermes backend is installed**

No Windows or WSL Hermes configuration was changed. No backend, listener,
systemd service, firewall rule, repair job, Docker command, or production
operation was started.

## Discovery result

The installed wrapper is:

```text
/home/jeff/.local/bin/hermes
```

It hard-codes the active Hermes root:

```text
/home/jeff/hermes-sandbox
```

Its supported help surface contains interactive Hermes, task/prompt helpers,
Telegram modes, and `--print-prompt`. It does not contain `serve`,
`dashboard`, a backend host/port option, `/api/status`, or a WebSocket
endpoint. `hermes serve --help` and `hermes dashboard --help` do not expose a
backend; the wrapper falls through to its interactive TUI path. Therefore
those strings cannot safely be treated as supported server commands.

## Current safety state

```text
swarm runtime: /home/jeff/hermes-swarm-runtime
requested bind: 127.0.0.1:9120 (not created)
kill switch: ENGAGED
deployment: DISABLED
original Hermes: untouched
/home/jeff/n8n: untouched
Windows Hermes configuration: untouched
```

Because no supported backend exists, there is no valid WSL `/api/status`,
WebSocket, or Windows localhost result to report. No fallback to
`0.0.0.0`, a LAN address, `--insecure`, or a custom HTTP/WebSocket shim was
used.

## Required next step

Install or provide the officially supported Hermes Desktop/backend CLI that
documents:

- a server or dashboard subcommand;
- an explicit loopback host and port;
- the `/api/status` endpoint;
- the WebSocket/chat endpoint and origin requirements;
- a supported configuration-root or profile argument.

Once that supported interface is available, the safe planned commands are:

```text
hermes-swarm desktop-backend start
hermes-swarm desktop-backend status
hermes-swarm desktop-backend stop
hermes-swarm kill-switch
```

They must use only `/home/jeff/hermes-swarm-runtime`, bind only to
`127.0.0.1:9120`, retain the engaged kill switch, and avoid credentials in
the unit. These commands are not installed yet because their backend target
cannot be resolved safely.

Do not enter `http://localhost:9120` in Windows Desktop until a supported
backend is installed and the WSL and Windows read-only connectivity checks
pass.
