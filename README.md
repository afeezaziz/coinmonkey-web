# Coin Monkey Website + Agent Runner (MVP)

This repository contains:

- Website/control plane (Flask) under project root
- Agent runner container (Docker) in `runner/`

The website lets you create agents, start/stop them, and view details. The base agent runner generates its own EVM keypair on first start and persists it in a per-agent Docker volume.

## Prerequisites

- Python 3.12+
- Docker Desktop or a local Docker daemon (only required if using the Docker orchestrator)

## Install and run the website (control plane)

```bash
# In the project root
pip install -r requirements.txt

# Run dev server (uses in-memory orchestrator by default)
python hello.py
# Visit http://127.0.0.1:5000
```

## Build the agent runner container

```bash
# From project root; builds the image using runner/Dockerfile
docker build -f runner/Dockerfile -t coinmonkey/agent-runner:dev .
```

## Use Docker orchestrator and launch an agent

```bash
# In a new shell, run Flask with Docker orchestrator and your local image
export ORCHESTRATOR=docker
export AGENT_IMAGE=coinmonkey/agent-runner:dev
python hello.py
```

Now visit:

- Create agent: http://127.0.0.1:5000/agents/new
- Agents list: http://127.0.0.1:5000/agents

Start the agent on its detail page. On first start, the container will:

- Generate an EVM keypair
- Persist it at `/data/agent_key.json` inside the container (backed by a named Docker volume: `agent-<agent_id>-data`)
- Expose health endpoints on port 8000 inside the container

## Inspect generated key/address

Check container logs (the agent logs the address on start):

```bash
docker logs agent-<agent_id> --since 10m | tail -n 100
```

Or inspect the Docker volume contents by temporarily running a helper container:

```bash
# Replace <agent_id> with the actual ID
docker run --rm \
  -v agent-<agent_id>-data:/data \
  busybox cat /data/agent_key.json
```

Note: Never expose private keys publicly. This is for local testing only.

## How it works (MVP)

- Control plane stores agent metadata in `agents.db` (SQLite via SQLAlchemy)
- Starting an agent asks the orchestrator to run a container:
  - Env vars provided: `AGENT_ID`, `AGENT_NAME`, `STRATEGY`, `CONFIG_JSON`, `KEYSTORE_PATH=/data`, `HEALTH_PORT=8000`
  - A per-agent named Docker volume is mounted at `/data` to persist the generated keypair
- The agent container runs a small Flask app for `/healthz`, `/readyz`, `/metrics` and a background loop that emits heartbeats

## Next steps

- Secure secret management and CEX/EVM credential injection
- Streaming logs in UI (SSE) and basic metrics display
- Strategy connectors for CEX and EVM RPCs
- Kubernetes backend for production

## Credentials and encryption (MVP)

- The control plane encrypts credential payloads at rest with `cryptography.Fernet`.
- Dev key management:
  - If `CM_ENCRYPTION_KEY` env var is set, it will be used (recommended for prod). It must be a Fernet key (urlsafe base64).
  - Otherwise, a local file `.secrets/fernet.key` is created automatically and used (ignored by git).
- UI pages:
  - Add EVM RPC URLs or CEX API keys on the Agent detail page (Credentials section).
  - On start/redeploy, decrypted credentials are injected into the container as env vars:
    - `EVM_RPC_URLS` (JSON array)
    - `CEX_EXCHANGE`, `CEX_API_KEY`, `CEX_API_SECRET`, `CEX_API_PASSPHRASE` (optional)
- Wallet and connectivity:
  - Runner exposes `/wallet` and `/cex` endpoints; the control plane proxies these at:
    - `/agents/<id>/wallet.json`
    - `/agents/<id>/cex.json`
  - The Agent page shows a Wallet and CEX Connectivity widget.

