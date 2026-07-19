# spt-txn-x402-escrow

**On-chain, trustless enforcement of SPT-Txn authorization for x402 payments on
Solana.**

A Solana (Anchor) program that holds an x402 payment in escrow and **releases it
only against a valid, in-scope SPT-Txn authorization proof** — verified on-chain
via the Ed25519 precompile and a fixed-width intent binding. It fails closed: a
missing or duplicate attestation, an issuer not on the allowlist, a binding
mismatch, stale freshness, or a replayed nonce all revert. This is the trustless
settlement path that complements the off-chain gate in
[spt-txn-x402-solana](https://github.com/rudizee007/spt-txn-x402-solana).

- **Deployed on devnet:** `JUYFyssaZLPb1fwTgNJG6MwmfQKnUvCvSmhjWA5sgdk`
- Spec: [`docs/SPEC.md`](docs/SPEC.md) · Threat model: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)

## What it enforces on-chain

- **Issuer signature authentic** — the native Ed25519 precompile plus instruction
  introspection; the program verifies no signature itself.
- **Issuer ∈ on-chain allowlist** — deny-by-default; nobody is authorized until
  explicitly added.
- **Binding matches this payment** — payer, mint, amount, recipient, resource, and
  nonce, compared constant-time.
- **Freshness** against the on-chain clock (short TTL).
- **Single use** — a spent-marker PDA makes replay structurally impossible.
- **No canonicalization on-chain** — a fixed-width binding only, so the classic
  issuer-vs-verifier canonicalization bypass is designed out.

## Security invariants

- **Deny by default, fail closed.** Every failure path reverts; escrowed funds are
  never released on a malformed or unauthorized request.
- **No ambient authority.** Release requires the transaction-scoped proof, never a
  role or a network position.
- **No custom cryptography.** The Ed25519 precompile and `sha2` only; constant-time
  comparison for secret-adjacent bytes.
- **Memory-safe trust boundary.** Rust / Anchor; no C or C++.

## Build & test

```sh
anchor build
cargo test -p spt_x402_escrow    # litesvm integration test
```

Requires the Anchor 1.1.2 / Solana 3.x / Rust 1.89 toolchain (see
`rust-toolchain.toml`).

## Status

Trust-boundary code. It has passed two adversarial "find the bypass" reviews and a
litesvm + differential test suite, and is deployed to devnet. Mainnet is gated on
a final human line-by-line review. Report vulnerabilities per
[`security.json`](security.json).

## License

Apache-2.0. Built on the open SPT-Txn reference implementation and the IETF
`draft-coetzee-oauth-spt-txn-tokens`.
