# How to Run Trust Gateway with Docker Compose

This guide explains how to get the Trust Gateway community ecosystem up and running using Docker Compose.

## Prerequisites

- **Docker** and **Docker Compose** installed on your machine.
- **curl** and **openssl** installed (standard on most Unix/Linux systems) to generate cryptographic keys and download the NATS helper CLI.

## Step-by-Step Instructions

### 1. Navigate to the Directory

Open a terminal and navigate to the `docker_experimental` directory:

```bash
cd lianxi-community/docker_experimental
```

### 2. Configure Optional Environment Variables (Optional)

If you have specific OAuth configurations (e.g. Google Calendar) or want to specify your edition/CORS allowed origins:
Create or update the `.env` file in the current directory. A default set of variables is automatically provided.

```bash
# Example .env configuration
EDITION=community
JWT_SECRET=your_persistent_jwt_secret # Optional: generated automatically if not set
```

### 3. Build and Launch the Ecosystem

Run the automated startup script:

```bash
./start.sh
```

This script will:
1. Generate the required Ed25519 grant signing key pair (`keys/grant_signing.pem` and `keys/grant_verify.pem`) if not already present.
2. Dynamically download the NATS `nk` CLI tool if it's not present.
3. Ephemerally generate cryptographic NATS nkeys for all services and write the NATS access control lists to `nats-server-auth.conf`.
4. Merge environment variables and NATS seeds into a temporary `.env.docker` file.
5. Boot all containers via Docker Compose.
6. Automatically spin up an initialization task (`nats-init`) to declare and configure JetStream KV buckets (`telegram_rate_limit`, `dht_discovery`).

### 4. Verify the Installation

Once all containers are built and running:

- **Local SSI Portal (UI)**: [http://localhost:8080](http://localhost:8080)
- **Trust Gateway API**: [http://localhost:3060/health](http://localhost:3060/health)
- **Agent Host API**: [http://localhost:3000/](http://localhost:3000/)
- **NATS Monitoring Portal**: [http://localhost:8222](http://localhost:8222)

---

## Service Topology in Docker

| Container Name | Port | Description |
|---|---|---|
| `nats` | 4222 / 8222 / 9222 | NATS Message Bus & WebSocket |
| `trust_gateway` | 3060 | Governance & Policy Engine |
| `agent_host` | 3000 | Sovereign Agent Host |
| `ssi_agent` | 8082 / 8083 | SSI Identity Agent |
| `executor_native` | - | Executor Host (Native Tool Profile) |
| `executor_connector` | - | Executor Host (Connector Profile) |
| `executor_vp` | - | Executor Host (VP Verification Profile) |
| `connector_mcp_helper` | 3050 | OAuth Helper (Connector MCP Server) |
| `local_ssi_portal` | 8080 | Portal Web Frontend (Nginx) |

---

## Troubleshooting

- **NATS Connection/Auth Errors**: The `./start.sh` script automatically regenerates and matches NATS seeds and credentials at startup. If you experience authentication failures, try stopping the containers and running `./start.sh` again to ensure all credentials sync.
- **Port Conflicts**: Ensure that host ports `3060`, `3000`, `3050`, `8080`, `4222`, `8222`, and `9222` are not in use by any other local services before starting.
- **Stale State / Clean slate**: To clear all NATS JetStream data and start completely fresh, remove the persistent volume:
  ```bash
  docker compose down -v
  ```
