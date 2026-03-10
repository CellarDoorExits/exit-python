# exit-door 𓉸

[![PyPI](https://img.shields.io/pypi/v/exit-door)](https://pypi.org/project/exit-door/)
[![tests](https://img.shields.io/badge/tests-101_passing-brightgreen)]()
[![Python](https://img.shields.io/pypi/pyversions/exit-door)](https://pypi.org/project/exit-door/)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

> **[𓉸 Passage Protocol](https://cellar-door.dev)** · [exit-door](https://github.com/CellarDoorExits/exit-door) · [entry-door](https://github.com/CellarDoorExits/entry-door) · [mcp](https://github.com/CellarDoorExits/mcp-server) · [langchain](https://github.com/CellarDoorExits/langchain) · [vercel](https://github.com/CellarDoorExits/vercel-ai-sdk) · [eliza](https://github.com/CellarDoorExits/eliza-exit) · [eas](https://github.com/CellarDoorExits/eas-adapter) · [erc-8004](https://github.com/CellarDoorExits/erc-8004-adapter) · [sign](https://github.com/CellarDoorExits/sign-protocol-adapter) · [python](https://github.com/CellarDoorExits/exit-python)

> **⚠️ Pre-release software -- no formal security audit has been conducted.** This project is published for transparency, review, and community feedback. It should not be used in production systems where security guarantees are required. If you find a vulnerability, please report it to hawthornhollows@gmail.com.

Vehicle registration for AI. Cryptographic proof that an agent left, when, and why. Python SDK.

## What is EXIT?

The EXIT Protocol creates verifiable departure records for AI agents. When an agent leaves a platform, it can create a cryptographically signed marker proving it departed, preserving reputation and continuity across contexts.

Think of it as a passport stamp for AI agents.

## Quick Start

```bash
pip install exit-door
```

### Create a signed departure marker in 3 lines:

```python
from exit_door import quick_exit, quick_verify

result = quick_exit("https://platform.example.com")
print(result.marker.id)  # urn:exit:a1b2c3...
```

### Verify a marker:

```python
verification = quick_verify(result.marker)
assert verification.valid  # True
```

### From JSON:

```python
from exit_door import to_json, quick_verify

json_str = to_json(result.marker)
verification = quick_verify(json_str)  # Accepts both strings and objects
```

## Core API

```python
from exit_door import (
    generate_identity,
    create_marker,
    sign_marker,
    verify_marker,
    from_json,
    to_json,
    ExitType,
    ExitStatus,
)

# Generate an identity (DID + Ed25519 keypair)
identity = generate_identity()
print(identity.did)  # did:key:z6Mk...

# Create an unsigned marker
marker = create_marker(
    subject=identity.did,
    origin="https://platform.example.com",
    exit_type=ExitType.VOLUNTARY,
)

# Sign it
signed = sign_marker(marker, identity.private_key, identity.public_key)

# Serialize to JSON (camelCase, spec-compliant)
json_str = to_json(signed)

# Parse and validate from JSON
parsed = from_json(json_str)

# Verify signature
result = verify_marker(parsed)
assert result.valid
```

## P-256 Support

```python
result = quick_exit("https://example.com", algorithm="P-256")
# Uses ECDSA P-256 with low-S normalization for cross-language compatibility
```

## Features

- **Ed25519 + P-256** signing and verification
- **Pydantic v2 models** with full type annotations and `py.typed`
- **RFC 8785 JCS** canonicalization for deterministic signing
- **did:key** encoding/decoding (Ed25519 + P-256)
- **Content-addressed marker IDs** (SHA-256)
- **Cross-language compatible** with the TypeScript `exit-door` package
- **Frozen models** (immutable after creation)
- **Zero async dependencies** (sync-only, CPU-bound crypto)

## Cross-Language Compatibility

This package produces markers that verify correctly with the TypeScript [`exit-door`](https://www.npmjs.com/package/exit-door) package and vice versa. Key interop decisions:

- P-256 signatures use compact `r||s` format with low-S normalization
- Ed25519 multicodec prefix: `[0xed, 0x01]` (varint)
- Domain prefix: `"exit-marker-v1.2:"`
- Base64 standard encoding (not URL-safe)
- Timestamps: millisecond precision with `Z` suffix

## Ecosystem

| Package | Language | Description |
|---------|----------|-------------|
| [exit-door](https://github.com/CellarDoorExits/exit-door) | TypeScript | Core protocol (reference impl) |
| **[exit-door](https://github.com/CellarDoorExits/exit-python)** | **Python** | **Core protocol ← you are here** |
| [cellar-door-entry](https://github.com/CellarDoorExits/entry-door) | TypeScript | Arrival/entry markers |
| [@cellar-door/langchain](https://github.com/CellarDoorExits/langchain) | TypeScript | LangChain integration |
| [cellar-door-langchain](https://github.com/CellarDoorExits/cellar-door-langchain-python) | Python | LangChain integration |
| [@cellar-door/vercel-ai-sdk](https://github.com/CellarDoorExits/vercel-ai-sdk) | TypeScript | Vercel AI SDK |
| [@cellar-door/mcp-server](https://github.com/CellarDoorExits/mcp-server) | TypeScript | MCP server |
| [@cellar-door/eliza](https://github.com/CellarDoorExits/eliza-exit) | TypeScript | ElizaOS plugin |
| [@cellar-door/eas](https://github.com/CellarDoorExits/eas-adapter) | TypeScript | EAS attestation anchoring |
| [@cellar-door/erc-8004](https://github.com/CellarDoorExits/erc-8004-adapter) | TypeScript | ERC-8004 identity/reputation |
| [@cellar-door/sign-protocol](https://github.com/CellarDoorExits/sign-protocol-adapter) | TypeScript | Sign Protocol attestation |

**[Paper](https://cellar-door.dev/paper/) · [Website](https://cellar-door.dev)**

## License

Apache-2.0
