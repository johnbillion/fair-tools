# Security policy

This package implements the FAIR protocol. Security design decisions are dictated by a combination of the FAIR protocol spec, the PLC DID spec, and restrictions of the PHP ecosystem.

## Design decisions

### Key generation and signing

Rotation keys are implemented with ECDSA [as required by the FAIR protocol spec](https://github.com/johnbillion/fair-protocol/blob/main/docs/implementing/repository.md#key-creation) and use the recommended secp256k1 curve. The secp256k1 implementation is provided by `@noble/curves` via the `@atproto/crypto` wrapper which uses the low-S form of signatures encoded in IEEE-P1363 format.

Verification keys are implemented with EdDSA using Ed25519. The FAIR protocol spec imposes no constraints on which algorithms can be used for verification keys. The Ed25519 implementation is provided by `@noble/curves`.

Ed25519 was chosen for interoperability with PHP:

1. FAIR originated as a protocol to be used within the WordPress ecosystem, which uses PHP. The Sodium extension and the sodium_compat library -- both widely used within the WordPress and PHP ecosystems -- [provide Ed25519 as the only algorithm for public key cryptography](https://github.com/paragonie/sodium_compat/issues/46).
2. The FAIR plugin for WordPress uses Ed25519 for verifying signatures for the same reason, and interoperability with existing FAIR tooling for WordPress is a key requirement of this package.

### Private key storage

Private keys are stored in PEM format, which enables detection by secret scanning services and tools:

| Key Type     | Algorithm | PEM Format | Header                           |
| ------------ | --------- | ---------- | -------------------------------- |
| Rotation     | secp256k1 | SEC1       | `-----BEGIN EC PRIVATE KEY-----` |
| Verification | ed25519   | PKCS#8     | `-----BEGIN PRIVATE KEY-----`    |

Key files are written with mode `0600` (owner read/write only).

### DID management

DID operations (creation, updates, key rotation) are performed via the `@did-plc/lib` library, which handles DAG-CBOR encoding, operation signing, and communication with the PLC directory.

All DID update operations must be signed by a rotation key. The package enforces safety constraints such as preventing revocation of the last rotation key or self-revocation of the signing key.

## Reporting a vulnerability

If you discover a security vulnerability in this package [please report it via the private security vulnerability reporting mechanism here on GitHub](https://github.com/johnbillion/fair-tools/security/advisories/new).
