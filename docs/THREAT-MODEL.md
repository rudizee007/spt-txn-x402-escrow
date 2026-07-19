# THREAT MODEL — spt_x402_escrow

Scope: the on-chain enforcement program only. The off-chain verifier has its own
threat model in the reference repo. Read `SPEC.md` first.

The attacker's goal is to make the escrow **release funds for a payment the issuer
did not authorize**, or to **trap/steal** escrowed funds. Ranked by likelihood and
impact.

---

## T1 — Canonicalization mismatch (CRITICAL, designed-out)
*Classic bypass class: the on-chain path derives the bound value differently than
the issuer did, so a payment the issuer never signed appears "bound."*
- **Mitigation (structural):** the program never canonicalizes. It compares the
  issuer-signed, fixed-width `binding` (SPEC §4) to the escrow's stored `binding`
  with a constant-time compare. There is no JSON, no map ordering, no re-hash of a
  structured request on-chain. The only hash the program computes is over a
  fixed-width, order-fixed byte layout — identical to the off-chain derivation by
  construction.
- **Residual:** the *fixed layout itself* must match the off-chain issuer exactly
  (field order, widths, endianness, domain tag). → **Differential test** the Go
  issuer and the Rust program against shared vectors (T-tests §T-test).

## T2 — "A precompile ran" confusion (CRITICAL)
*Attacker includes a valid Ed25519 instruction for a message/pubkey of their
choosing, and the program releases because it only checked that "some" Ed25519
instruction was present.*
- **Mitigation:** `release_with_proof` reads the Instructions sysvar and binds the
  precompile instruction's `pubkey` (∈ allowlist) and `message` (= the exact
  `token_msg` it parses `binding`/`iat` from). A precompile over any other pubkey
  or message does not satisfy the check. (SPEC §6, §7.2.)
- **Residual:** parsing `token_msg` must be total and unambiguous — a malformed
  message must DENY, never partial-match. → fuzz the parser (T-test).

## T3 — Wrong / rogue issuer (HIGH)
*Attacker signs a token with their own Ed25519 key.*
- **Mitigation:** deny-by-default `IssuerAllowlist` set at program init by an admin
  PDA. Signer ∉ allowlist → DENY_VIOLATION. Allowlist changes are admin-gated and
  logged. Empty/uninitialized allowlist → DENY_UNAVAILABLE (never allow-all).

## T4 — Replay of a valid release (HIGH)
*Attacker replays a previously valid `release_with_proof`.*
- **Mitigation:** the Escrow PDA is closed on release; a second release finds no
  account → DENY. Escrow PDA is derived from `["escrow", payer, recipient,
  binding]`, so a given binding maps to a single escrow. Token freshness
  (`MAX_TOKEN_AGE_SLOTS`) bounds the window even before close.
- **Cross-escrow replay (was a CRITICAL bug; fixed).** An adversarial review found
  that an earlier binding covered only `(mint, amount, recipient, resource_id)`, so
  every escrow for an identical order shared one binding and a single attestation
  could release all of them — the beneficiary sweeping funds the issuer never
  individually authorized. Identical concurrent x402 orders make this the normal
  case, not an edge case. **Fix:** `binding` now includes `payer` and a
  per-authorization `nonce` (SPEC §4), making it instance-unique — one attestation
  is valid for exactly one escrow. The escrow PDA seed includes this binding, so A
  and B are distinct accounts with distinct bindings and no attestation crosses
  between them.
- **Test obligation:** the escrow-conservation property test MUST include the
  adversarial case of *N escrows created for an identical order* and assert one
  attestation releases at most the single escrow it was issued for.

## T5 — Escrow drain / fund theft (HIGH)
*Attacker redirects release or refund to themselves.*
- **Mitigation:** `recipient` and `payer` are fixed in the Escrow account at
  `init_escrow` and are not parameters of release/refund. Release pays the stored
  `recipient`; refund pays the stored `payer`. Anchor `has_one`/seed constraints
  bind the vault, mint, and destinations. No instruction accepts an
  attacker-chosen destination.

## T6 — Trapped funds / liveness (MEDIUM)
*A release never comes (issuer offline, agent abandoned); funds stuck.*
- **Mitigation:** `refund_expired` after `expiry_slot` returns funds to `payer`;
  callable by anyone (only the destination is fixed). Custody is safe and liveness
  is preserved without weakening authorization.

## T7 — Freshness / clock manipulation (MEDIUM)
*Old token reused; or reliance on a spoofable timestamp.*
- **Mitigation:** freshness uses the on-chain `Clock`/slot, not a client value.
  `iat` is read from the signed `token_msg` (issuer-attested) and must be within
  `MAX_TOKEN_AGE_SLOTS` of the current slot. Both bounds enforced.

## T8 — Arithmetic / account-model faults (MEDIUM)
*Overflow on amounts; wrong mint; fake token accounts.*
- **Mitigation:** checked arithmetic only (`checked_add`/`checked_sub`, DENY on
  `None`). SPL transfers via CPI to the token program with `mint` and `owner`
  constraints; vault is a PDA-owned ATA. No raw lamport math on SPL paths.

## T9 — Admin/allowlist compromise (MEDIUM, governance)
*Admin key rotates in a rogue issuer.*
- **Mitigation:** admin is a PDA with a documented, separately-held upgrade
  authority; allowlist changes emit events for the transparency log. Out-of-band
  monitoring. (Program-upgrade authority governance is documented in deploy notes,
  not code.)

---

## Test obligations (T-test) — gate before mainnet

- **Differential vectors:** shared `binding` test vectors; assert Go issuer and
  Rust program produce identical bytes for the same primitive fields. (T1)
- **Property test — issuer allowlist:** for random signers, release succeeds iff
  signer ∈ allowlist and binding matches; never otherwise. (T2, T3)
- **Property test — escrow conservation:** across random sequences of
  init/release/refund, total lamports/tokens are conserved; no path pays a
  non-`recipient`/non-`payer`; no double release. (T4, T5)
- **Fuzz** `token_msg` parsing: every malformed input DENYs, no panic, no
  partial-match. (T2)
- **Negative matrix:** each DENY path asserts the correct decision class
  (`DENY_VIOLATION` vs `DENY_UNAVAILABLE`). (SPEC §8)

## Second adversarial pass — findings & status

- **T10 — Sequential replay via close-and-reinit (was HIGH; fixed).** Single-use
  had relied on the escrow closing on release, but a closed PDA can be
  re-initialized, and the attestation is a permanent public on-chain artifact.
  Within the freshness window a captured attestation could release a re-created
  escrow with the same nonce. **Fixed** with a permanent spent-marker PDA
  `["spent", binding]` created on release and never closed (SPEC §5.2 step 5).
- **T11 — Vault dust-griefing → permanent fund lock (was HIGH; fixed).** A 1-unit
  dust transfer into the vault made the fixed-`amount` transfer leave a residual,
  so `close_account` reverted and both release and refund became permanently
  impossible. **Fixed** by transferring the vault's live balance before close.
- **T9 (admin bootstrap) — was MED/HIGH; fixed.** `init_config` was
  unauthenticated (first caller became admin and could allowlist a rogue issuer).
  **Fixed:** `init_config` now requires `admin` to be the program's **upgrade
  authority**, checked via the `ProgramData` account, with the `ProgramData` tied
  to this program through `program.programdata_address()`. The init front-run is
  no longer possible; only the deployer can set the admin. Verified in the litesvm
  integration test (init_config succeeds only when `admin` is the upgrade
  authority). NOTE: this requires the program to be deployed **upgradeable** with a
  real upgrade authority; an immutable (authority = None) deployment cannot run
  `init_config` and must set the admin another way.

## Review gate

1. Implement against SPEC.
2. Adversarial review, fresh context: *"Assume this contains an authorization
   bypass. Find it."*
3. The tests above, all green.
4. Human line-by-line review (maintainer).
5. Novelty scan + provisional (if warranted) **before** any public push.

No devnet-to-mainnet promotion, and no public repo, until 1–5 are done.
