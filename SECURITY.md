# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in this package, please report it responsibly.

**Email:** hawthornhollows@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Security Considerations

This is a **pre-release** cryptographic library. While it uses well-established cryptographic primitives (Ed25519, P-256 via the `cryptography` library), it has not undergone a formal security audit.

**Do not use in production environments where cryptographic guarantees are critical without independent review.**

### Known Limitations

- Ed25519 verification uses OpenSSL strict RFC 8032 mode (not ZIP-215)
- Key material zeroing via `Signer.destroy()` is best-effort due to Python GC
- No constant-time comparison for signature bytes (delegated to `cryptography` library)
