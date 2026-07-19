# ADR-001: Rust toolchain and HTTP stack

## Status

Accepted

## Date

2026-07-20

## Context

rvuln0-scan needs to perform HTTP requests against remote services at scale.
Key requirements:
- Async concurrency for parallel target scanning
- TLS support with custom certificate verification (inspect bad certs)
- Proxy support, redirect handling, custom headers
- Minimal dependency footprint

## Decision

Use `tokio` + `reqwest` + `rustls` for all HTTP/TLS operations.

- `tokio` — async runtime (industry standard for Rust async)
- `reqwest` — high-level HTTP client built on `hyper` and `tokio`
- `rustls` — native Rust TLS (no OpenSSL dependency)

`reqwest` configured with `rustls-tls` feature (not native-tls) to avoid
linking against system OpenSSL — simpler cross-compilation and CI.

## Alternatives Considered

### hyper directly
- Pros: More control, fewer abstractions
- Cons: Significantly more boilerplate for cookie handling, redirects, headers
- Rejected: reqwest provides the right level of abstraction for a scanner

### curl bindings (curl-rust)
- Pros: Battle-tested, supports everything
- Cons: External C dependency, complex build, unsafe FFI
- Rejected: Avoids C deps entirely

### isahc
- Pros: Also Rust-native HTTP
- Cons: Smaller ecosystem, less community support
- Rejected: reqwest has wider adoption and better documentation

## Consequences

- No OpenSSL dependency — simpler builds on all platforms
- `reqwest` handles connection pooling, retries, redirects
- Need `rustls` `dangerous_configuration` for custom cert verification
- Updating `reqwest` may require syncing `hyper` and `rustls` versions
