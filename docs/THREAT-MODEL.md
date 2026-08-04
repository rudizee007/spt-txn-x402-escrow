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
- **Mitigation:** deny-by-default `IssuerAllowlist`, admin-gated and logged.
  Signer ∉ allowlist → DENY_VIOLATION. Empty/uninitialized allowlist →
  DENY_UNAVAILABLE (never allow-all).
- **Second, independent gate:** allowlist membership is necessary but not
  sufficient. The signer must also equal the issuer the payer pinned at deposit.
  An attacker who obtains allowlist membership — including by compromising the
  admin — still cannot release an escrow pinned to someone else. See T9.

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

## T9 — Admin/allowlist compromise (LOW residual, structurally mitigated)
*The admin key is stolen and the attacker allowlists an issuer they control.*

This is the strongest custody objection anyone can raise against the design, so
it is answered structurally rather than procedurally: **a fully compromised admin
key cannot cause a single unauthorized release.**

- **Mitigation — issuer pinning, ANDed with the allowlist.** At `init_escrow` the
  payer names the one issuer whose attestation can ever release *that* escrow;
  the program stores it immutably in `Escrow.issuer` (SPEC §5.1). At release the
  attesting key must equal that pin **and** still be on the allowlist — both
  checks, never one substituted for the other (`lib.rs::release_with_proof`
  steps 3 and 3b). An issuer added *after* a deposit fails the pin, because the
  pin predates the compromise and no instruction can edit it. Error 6108
  `IssuerNotPinned`.
- **Why both checks, not just the pin:** the allowlist is what makes revocation
  immediate. Remove a compromised issuer and every escrow already in flight stops
  releasing on the next block. Dropping the allowlist in favour of the pin alone
  would trade a governance risk for a worse one.
- **What a compromised admin can still do:** remove a legitimate issuer, which
  stops *new* releases. It cannot cause one. The worst reachable outcome is that
  in-flight escrows expire and `refund_expired` returns every payer's funds to
  the payer. The admin is a denial-of-service role, not a custody role. That
  distinction is the whole claim.
- **Separation of duties, enforced at runtime rather than by deploy convention.**
  `init_config` has the **upgrade authority** sign — which is what closes the
  init front-run — while *naming a different key* as admin. The account
  constraints reject the transaction if one key would hold both
  (`AdminIsUpgradeAuthority`). The same check runs again at `accept_admin`, so a
  later rotation cannot silently re-collapse the two roles.
- **Handover is two-step:** `propose_admin` (outgoing admin signs), then
  `accept_admin` (nominee signs). A mistyped or hostile nomination has no effect
  until the nominee proves possession of the key. Nothing changes on chain in
  between.
- **Residual risk is the program upgrade, not the admin key.** Whoever holds the
  upgrade authority can deploy code without the pin check. The mitigation is
  procedural: hold it in a multisig behind a timelock. `MAX_ESCROW_SECS` is 900
  (15 minutes), so any timelock longer than 15 minutes guarantees every in-flight
  escrow has already expired — and refunded — before new code can land. A 24-hour
  timelock is a 96× margin. Burning the upgrade authority is *not* the answer: an
  immutable deployment cannot run `init_config` at all.
- **Allowlist changes emit `IssuerAdded`/`IssuerRemoved`** for the transparency
  log and out-of-band monitoring. This is now detection, not the control.
- **Evidence:** `cmd/escrowdevnet -mode deny-unpinned` (reference repo) runs this
  attack on devnet with the admin key in hand. The `add_issuer(rogue)` succeeds —
  the admin really can do it — and the release still fails 6108. The argument is
  an explorer link, not a paragraph.

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
  **Fixed:** `init_config` is authenticated against the program's **upgrade
  authority**, checked via the `ProgramData` account, with the `ProgramData` tied
  to this program through `program.programdata_address()`. The init front-run is
  no longer possible; only the deployer can set the admin. NOTE: this requires the
  program to be deployed **upgradeable** with a real upgrade authority; an
  immutable (authority = None) deployment cannot run `init_config` and must set
  the admin another way.

- **T9 (role concentration) — the first fix was itself the next finding; fixed.**
  The bootstrap fix above made the upgrade authority *become* the admin. That
  closed the front-run and immediately opened a worse hole: one key held the
  power to change the code **and** the power to change the issuer allowlist. A
  single compromise was then total, and "who controls customer funds" had exactly
  one honest answer — the operator. **Fixed** by separating the two roles at
  runtime (the upgrade authority signs `init_config` but a *different* key is
  named admin, enforced by account constraint) and, more importantly, by removing
  the admin from the release path altogether via issuer pinning. See T9 above for
  the full argument. Verified in the litesvm suite
  (`programs/spt_x402_escrow/tests/integration.rs`) by eight tests:
  `happy_path_then_replay_blocked`,
  `compromised_admin_cannot_release_a_pinned_escrow`,
  `revoked_issuer_cannot_release_even_when_pinned`,
  `cannot_pin_an_unauthorized_issuer`,
  `init_config_refuses_to_collapse_the_two_roles`,
  `init_config_rejects_a_non_upgrade_authority_signer`,
  `admin_rotation_is_two_step_and_transfers_the_role`, and
  `admin_rotation_refuses_the_upgrade_authority`.

  Worth recording plainly: the fix that closes one finding is a normal place for
  the next one to appear. The bootstrap patch was correct about front-running and
  wrong about custody, and nothing in the first review caught that because the
  review question was "can an attacker seize the admin role", not "what does the
  admin role let its legitimate holder do".

## Review gate

1. Implement against SPEC.
2. Adversarial review, fresh context: *"Assume this contains an authorization
   bypass. Find it."*
3. The tests above, all green.
4. Human line-by-line review (maintainer).
5. Novelty scan + provisional (if warranted) **before** any public push.

No devnet-to-mainnet promotion, and no public repo, until 1–5 are done.
