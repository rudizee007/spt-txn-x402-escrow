# Security

## Reporting a vulnerability

Report privately to **rudi@violetskysecurity.com**. Please allow reasonable time
for remediation before public disclosure; coordinated disclosure is appreciated.
Machine-readable contact details are in [`security.json`](security.json).

## What this program is trusted to do

`spt_x402_escrow` holds funds in a vault PDA and releases them only against an
Ed25519 attestation, issued by an allow-listed key, bound to that exact escrow.

Four properties carry the weight:

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

**No operator role can cause a release.** At deposit the payer names the one
issuer key permitted to release that escrow, and the program stores it
immutably. Release requires the attesting key to equal that pin **and** to be on
the allowlist — both, never either. Since no instruction can edit a stored pin,
an attacker holding the admin key can add an issuer they control and still not
release a single existing escrow; the worst they achieve is refusing new
releases, after which `refund_expired` returns every payer's funds to the payer.
Separation of duties is enforced by the account constraints rather than by
deploy notes: `init_config` has the upgrade authority sign while naming a
*different* key as admin, and the same check runs again at `accept_admin` so a
later rotation cannot re-merge the roles. Admin handover is two-step — nominate,
then the nominee signs to claim it. See [`THREAT-MODEL.md`](THREAT-MODEL.md) T9
and [`SPEC.md`](SPEC.md) §5.4.

## Dependency audit status

Last run **2026-08-04** against `RustSec/advisory-db` (1186 advisories),
414 crate dependencies.

`cargo audit` reports two vulnerabilities, one unsoundness warning, and five
unmaintained-crate warnings. **None of the three defects is present in the
deployed program.** All arrive through `[dev-dependencies]`:

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

Worth stating precisely, because it is checkable: RUSTSEC-2024-0344's own
remediation is *upgrade to >= 4.1.3*, and the program's normal dependency tree
already resolves `curve25519-dalek 4.1.3`. Only the test harness's second copy
sits at the affected 3.2.0.

Both are genuine defects in general-purpose cryptographic libraries. Neither is
reachable here, and neither is patchable from this repository: the versions are
pinned by `agave-precompiles` via `litesvm`, not by anything under our control.
`cargo update -p litesvm` moves nothing, which is the check that confirms the
pin is upstream rather than a stale lockfile here. They will clear when
`litesvm` updates.

### Unsoundness warning — `rand 0.7.3`

| Advisory | Crate | Status |
|---|---|---|
| [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097) | `rand 0.7.3` | Not in the deployed program. The unsoundness requires a **custom global logger that calls `rand::rng()` reentrantly**; nothing in this crate installs a logger, and the affected version is reachable only from the test harness. |

`cargo audit` classifies this one as *unsound* rather than *unmaintained*, so it
is recorded here rather than in the maintenance list below — it is a soundness
defect, not a maintenance note. It enters the graph twice, via
`ed25519-dalek 1.0.1` and `libsecp256k1 0.6.0`, both of which sit beneath
`agave-precompiles 3.1.14`, itself reached only through the `litesvm`
`[dev-dependencies]` entry. The program's
own tree resolves `rand 0.8.7`, which predates the `rand::rng()` API the
advisory concerns.

### Unmaintained-crate warnings

Five crates are flagged unmaintained: `ansi_term`, `bincode`, `derivative`,
`libsecp256k1`, and `paste`. These are advisories about maintenance status
rather than defects, and all arrive transitively through the Solana and Anchor
toolchains. They are listed for completeness rather than presented as findings.

### Reconciling with GitHub's Dependabot

Dependabot shows **three** open alerts where `cargo audit` shows two
vulnerabilities: it surfaces the `rand` unsoundness alongside the two `*-dalek`
advisories, and it does not separate the two classes. All three resolve to the
same `litesvm` dev-dependency chain documented above. Dependabot reports them
because it scans `Cargo.lock`, which records the complete graph including
dev-dependencies without distinguishing them; the alert is accurate about the
lockfile and misleading about the program. They are therefore dismissed in this
repository as *vulnerable code is not actually used*, with this section as the
standing justification.

### Reproduce

```sh
cargo audit
cargo tree -p spt_x402_escrow --edges normal | grep -E 'dalek|rand'
cargo tree -p spt_x402_escrow -i curve25519-dalek@3.2.0
cargo tree -p spt_x402_escrow -i ed25519-dalek@1.0.1
cargo tree -p spt_x402_escrow -i rand@0.7.3
```

The first tree is the program's real dependency graph, with dev-dependencies
excluded. No affected version appears in it.

## Building

Build with `cargo build-sbf`, never `anchor build` — see the build section in
[`README.md`](README.md) for why, and verify the compiled program declares the
correct ID before any upgrade.
