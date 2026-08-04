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

- **Deployed on devnet:** [`C9kTmtYm5V8cFfNvgzJAcVfM2zYN1Pqv245Xe27h4NwZ`](https://explorer.solana.com/address/C9kTmtYm5V8cFfNvgzJAcVfM2zYN1Pqv245Xe27h4NwZ?cluster=devnet) — upgrade authority held by the deployer, issuer-allowlist admin held by a **different** key (the program refuses to let one key hold both).
- Spec: [`docs/SPEC.md`](docs/SPEC.md) · Threat model: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)

## What it enforces on-chain

- **Issuer signature authentic** — the native Ed25519 precompile plus instruction
  introspection; the program verifies no signature itself.
- **Issuer ∈ on-chain allowlist** — deny-by-default; nobody is authorized until
  explicitly added.
- **Issuer == the key this payer pinned at deposit** — ANDed with the allowlist,
  never substituted for it. The pin is immutable, so no admin action can make an
  existing escrow releasable by a newly added key.
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
- **No operator holds custody.** The admin's entire power is to edit the issuer
  allowlist and hand the role over. A fully compromised admin key cannot cause a
  single unauthorized release — the worst it achieves is that in-flight escrows
  expire and refund to their payers. Separation from the upgrade authority is an
  account constraint, not a deploy note, and admin handover is two-step.
- **No custom cryptography.** The Ed25519 precompile and `sha2` only; constant-time
  comparison for secret-adjacent bytes.
- **Memory-safe trust boundary.** Rust / Anchor; no C or C++.

## Build & test

```sh
cargo build-sbf --manifest-path programs/spt_x402_escrow/Cargo.toml
cargo test -p spt_x402_escrow    # litesvm integration test
```

**Do not run `anchor build`** — it rewrites `declare_id!` before compiling and
produces a binary that bricks the deployed program. The reason is spelled out
below.

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

## Building — use `cargo build-sbf`, not `anchor build`

The program keypair that originally chose the address
`C9kTmtYm5V8cFfNvgzJAcVfM2zYN1Pqv245Xe27h4NwZ` is not on this machine. Anchor
syncs `declare_id!` and `Anchor.toml` from `target/deploy/*-keypair.json`
*before* it compiles, so `anchor build` silently rewrites both files to whatever
keypair it finds or generates, and produces a binary that declares the wrong ID.
Deploying that binary bricks the program: Anchor's runtime ID check rejects
every instruction before your code runs.

Build with:

    cargo build-sbf --manifest-path programs/spt_x402_escrow/Cargo.toml

Upgrade with:

    solana program deploy target/deploy/spt_x402_escrow.so \
      --program-id C9kTmtYm5V8cFfNvgzJAcVfM2zYN1Pqv245Xe27h4NwZ \
      --url devnet --upgrade-authority ~/.config/solana/id.json

The upgrade authority signs upgrades; the program keypair is only needed for a
first deploy, which is already done. A `pre-commit` hook refuses any commit where
`declare_id!` has drifted.
