# Unicity Deployment

Docker-based deployment for Unicity nodes.

## Directory Structure

```
deploy/
├── ansible/               # Ansible automation
│   ├── inventory.yml.example  # Server inventory template
│   ├── deploy-simple.yml  # Main deployment playbook
│   └── ansible.cfg        # Ansible configuration
└── docker/                # Docker containerization
    ├── Dockerfile         # Multi-stage build for node
    └── docker-entrypoint.sh  # Container entry point
```

## Quick Start

### Build Docker Image Locally

```bash
# From project root
docker build -f deploy/docker/Dockerfile -t unicity:latest .
```

### Run Local Node

```bash
docker run -d \
  --name unicity \
  -p 9590:9590 \
  -v ~/.unicity:/home/unicity/.unicity \
  -e UNICITY_NETWORK=mainnet \
  unicity:latest
```

### Deploy to Remote Nodes

See `ansible/README.md` for Ansible deployment instructions.

## Network Ports

- **Mainnet**: 9590
- **Testnet**: 19590
- **Regtest**: 29590

## Notes

- RPC uses Unix domain sockets (`datadir/node.sock`) for security
- Seed nodes are configured in `src/chain/chainparams.cpp`
- Inbound connections enabled by default (set `UNICITY_LISTEN=0` to disable)
