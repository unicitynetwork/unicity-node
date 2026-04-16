# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities via public GitHub issues.**

If you discover a security vulnerability in unicity-node, please report it responsibly:

1. **Email**: Send a detailed report to the maintainers via the contact listed on the
   [Unicity Network GitHub organization](https://github.com/unicitynetwork).
2. **Subject line**: Use `[SECURITY] unicity-node - <brief description>`
3. **Include in your report**:
   - A description of the vulnerability and its potential impact
   - Step-by-step reproduction instructions
   - Any proof-of-concept code (if applicable)
   - Your suggested fix (if you have one)

## Response Timeline

- **Acknowledgement**: Within 48 hours of receipt
- **Initial assessment**: Within 7 days
- **Fix + disclosure**: Within 90 days (coordinated disclosure)

## Scope

The following are considered in-scope for security reports:

- Consensus rule bypass or manipulation
- Remote code execution via P2P messages or RPC
- Denial-of-service attacks against node operation
- Memory safety issues (buffer overflows, use-after-free, etc.)
- Supply chain issues in dependencies (especially RandomX)
- Eclipse attack vectors not already mitigated
- Cryptographic weaknesses

The following are **out of scope**:

- Issues in third-party dependencies that are already publicly known
- Bugs that require physical access to the machine running the node
- Theoretical attacks with no practical exploit path

## Security Best Practices for Node Operators

- Run the node as a non-root user
- Keep the RPC Unix socket (`/tmp/unicity.sock` by default) accessible only to trusted local processes
- Regularly update to the latest `main` branch commit
- Monitor the node process for unexpected resource usage
- If using Docker, use the provided multi-stage image which runs as a non-root user

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available and deployed, we will publish a
security advisory on the GitHub repository. Credit will be given to the reporter unless
they prefer to remain anonymous.
