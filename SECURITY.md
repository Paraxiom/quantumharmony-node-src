# Security Policy

## Project Status

QuantumHarmony runs as a test network of three validators operated by Paraxiom. It is not production and has not been audited.

## Supported Versions

| Version | Status |
| ------- | ------ |
| runtime spec 46 | Test network |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Email security concerns to: sylvain@paraxiom.org
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Varies by severity

## Scope

### In Scope
- SPHINCS+ signature implementation
- Consensus mechanism vulnerabilities
- Key management in `pallet-sphincs-keystore`
- Runtime security issues
- Cryptographic primitive misuse

### Out of Scope
- Known limitations documented in README
- Issues in upstream dependencies (report to respective projects)
- Denial of service on testnet (expected for research network)
- Social engineering attacks

## Known Limitations

This is a research testnet. Known security considerations:

1. **No Security Audit**: Code has not been professionally audited
2. **Experimental Cryptography**: Post-quantum primitives are implemented for research
3. **Classical transport and randomness**: links between validators use Noise, and randomness is classical
4. **No economic value**: QMHY is a test unit for fees. It is not sold

## Cryptographic Components

| Component | Implementation | Status |
|-----------|---------------|--------|
| SPHINCS+ | pqcrypto-sphincsplus | Research Implementation |
| Keccak-256 | sha3 crate | Standard Implementation |
| Falcon-512 | entries | Research Implementation |

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities (with permission).
