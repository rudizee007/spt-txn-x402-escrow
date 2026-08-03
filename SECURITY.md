# Security

## Reporting a vulnerability

Report privately to **rudi@violetskysecurity.com**. Please allow reasonable time
for remediation before public disclosure; coordinated disclosure is appreciated.
Machine-readable contact details are in [`security.json`](security.json).

## What this program is trusted to do

`spt_x402_escrow` holds funds in a vault PDA and releases them only against an
Ed25519 attestation, issued by an allow-listed key, bound to that exact escrow.

Three properties carry the weight:

**The program holds no key material.** There is no secret in the program, in any
account it owns, or in the deployed binary. Signing happens off-chain; the
issuer key lives outside any repository at mode 0600.

**The program verifies no signature itself.** Verification is performed by the
validator's native Ed25519 precompile. The program uses instruction-sysvar
introspection to read back the `(pubkey, message)` pair the runtime already
verified, and requires all three `*_ix` offset fields to be the `0xFFFF`
self-sentinel so the verified data cannot be sourced from another instruction.
No hand-rolled cryptography exists in this codebase.

**Deny-by-default is on-chain state, not documentation.** `init_config` creates
the allowlist **empty**, in its own transaction. Issuers are authorized
separately by `add_issuer`, which requires the recorded admin. `init_config`
itself refuses any signer that is not the program's recorded upgrade authority,
which closes the config front-run.

## Dependency audit status

Last run **2026-08-03** against `RustSec/advisory-db` (1186 advisories),
414 crate dependencies.

`cargo audit` reports two vulnerabilities and six unmaintained-crate warnings.
**Neither vulnerability is present in the deployed program.** Both arrive
through `[dev-dependencies]`:

```
curve25519-dalek v3.2.0
└── ed25519-dalek v1.0.1
    └── agave-precompiles v3.1.14
        └── litesvm v0.10.0
            [dev-dependencies]
            └── spt_x402_escrow
```

`litesvm` is the integration-test harness. Its `precompiles` feature is required
because the test suite exercises the same Ed25519 precompile path the program
depends on at runtime. Cargo does not link dev-dependencies into a library or
program build, so neither crate is compiled into `spt_x402_escrow.so`. The
artifact deployed at `C9kTmtYm5V8cFfNvgzJAcVfM2zYN1Pqv245Xe27h4NwZ` does not
contain them.

| Advisory | Crate | Status |
|---|---|---|
| [RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093) | `ed25519-dalek 1.0.1` | Not in the deployed program. The advisory is a **signing-side** oracle requiring the sign API with an attacker-influenced public key; this program never signs. |
| [RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344) | `curve25519-dalek 3.2.0` | Not in the deployed program. The advisory is a **timing side-channel**; an on-chain program processes no secrets — every input, account and execution step is public and deterministically replayable — so there is nothing for the channel to leak. |

Both are genuine defects in general-purpose cryptographic libraries. Neither is
reachable here, and neither is patchable from this repository: the versions are
pinned by `agave-precompiles` via `litesvm`, not by anything under our control.
They will clear when `litesvm` updates upstream.

GitHub's Dependabot reports these because it scans `Cargo.lock`, which records
the complete graph including dev-dependencies and does not distinguish them. The
badge is accurate about the lockfile and misleading about the program.

### Unmaintained-crate warnings

Six crates are flagged unmaintained or unsound: `ansi_term`, `bincode`,
`derivative`, `libsecp256k1`, `paste`, and `rand 0.7.3`. These are advisories
about maintenance status, not vulnerabilities, and all arrive transitively
through the Solana and Anchor toolchains. They are listed here for completeness
rather than presented as findings.

### Reproduce

```sh
cargo audit
cargo tree -i curve25519-dalek@3.2.0
cargo tree -i ed25519-dalek@1.0.1
```

## Building

Build with `cargo build-sbf`, never `anchor build` — see the build section in
[`README.md`](README.md) for why, and verify the compiled program declares the
correct ID before any upgrade.
