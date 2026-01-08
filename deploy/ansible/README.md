# Unicity Ansible Deployment

Ansible automation for deploying Unicity nodes via Docker.

## Quick Start

1. **Copy the inventory template:**
   ```bash
   cp inventory.yml.example inventory.yml
   ```

2. **Edit `inventory.yml`** with your server details:
   - Replace placeholder IPs with actual server addresses
   - Update SSH key path
   - Set network type (mainnet, testnet, regtest)

3. **Install Ansible prerequisites:**
   ```bash
   # macOS
   brew install ansible

   # Ubuntu/Debian
   sudo apt install ansible

   # Install Docker module
   ansible-galaxy collection install community.docker
   ```

4. **Deploy:**
   ```bash
   ansible-playbook -i inventory.yml deploy-simple.yml
   ```

## Files

| File | Description |
|------|-------------|
| `deploy-simple.yml` | Main deployment playbook |
| `inventory.yml.example` | Inventory template (copy to inventory.yml) |
| `.env.example` | Environment template |
| `ansible.cfg` | Ansible configuration |


## Docker Configuration

The deployment uses the Dockerfile in `../docker/`:
- Multi-stage build for minimal image size
- Non-root container user
- Configurable via environment variables

See `../README.md` for Docker usage details.
