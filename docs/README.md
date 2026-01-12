# Documentation Hub

Central index for Unicity PoW documentation. These links point to the canonical docs located throughout the repo so each area owns its docs close to the code.

- Architecture
  - [Architecture](ARCHITECTURE.md)
- Protocol
  - [Protocol Specification](SPECIFICATION.md)
- Testing
  - [Test Suite](../test/README.md) — Test suite documentation
  - [Functional Tests](../test/functional/README.md) — Python functional tests
- Deployment
  - [Deployment](../deploy/README.md) — Docker images, Compose, Ansible
- Fuzzing
  - [Fuzzing](../fuzz/README.md) — Building/running fuzz targets, corpus
- Tools
  - [Genesis Miner](../tools/genesis_miner/README.md) — Genesis/mining utilities
- Wire Testing
  - [Node Simulator](../test/wire/README.md) — Wire-level adversarial injector (real TCP)
- Development
  - [Sanitizers](SANITIZERS.md) — Address/Thread/UB sanitizers and usage

Notes
- Prefer linking to this hub from READMEs rather than duplicating or symlinking files into docs/.
- Keep docs co-located with the code they describe; update links here when you add new areas.
