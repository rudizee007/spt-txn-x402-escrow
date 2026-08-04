# SPEC — On-chain Enforcement of SPT-Txn Authorization for x402 (Solana)

Status: **implemented; deployed to Solana devnet.** Trust-boundary.

---

## 1. Purpose and scope

Provide a **second, independent, trustless** enforcement of SPT-Txn authorization
for an x402 payment: a Solana program holds the payment in escrow and releases it
only against a valid, in-scope SPT-Txn proof. This complements — does not replace
— the off-chain 8-step verifier.

**In scope:** escrow custody of an x402 payment (USDC/SPL or SOL); on-chain
verification of the SPT-Txn issuer signature; on-chain binding of the payment to
the token's committed digest; fail-closed release/refund.

**Explicitly out of scope on-chain:** JSON canonicalization (JCS), trust-registry
resolution, revocation status-list lookups, delegation-chain walking, zkDID/human
-anchor proof verification. These remain the off-chain verifier's responsibility
(§3). Attempting them on-chain is a non-goal and, for canonicalization, a
prohibited anti-pattern (§7).

---

## 2. Background: what the off-chain system already computes

From the published SPT-Txn reference implementation:

- The **SPT-Txn token** is a JWS signed with the `tts_issuer` **Ed25519** key. Its
  claims include `spt_txn_context_hash` (hex SHA-256 binding the token to a
  specific transaction) and, optionally, `spt_intent_digest` =
  `base64url(SHA-256(domainTag ‖ 0x00 ‖ JCS(intent)))`.
- The **8-step offline verifier** checks: signature, issuer trust, temporal
  bounds, revocation, scope ⊆ ceiling, delegation depth, humanAnchor consistency,
  and context-hash binding — each fail-closed.

The token therefore already carries a signed, self-contained commitment to *the
exact payment it authorizes*. The on-chain program's job is to re-check the two
parts of that commitment that a chain can verify **without re-deriving anything**:
the issuer signature, and equality of the committed digest to what the escrow was
created for.

---

## 3. Invariant split (the load-bearing decision)

| Invariant | Enforced where | Why |
|---|---|---|
| Issuer signature authentic (Ed25519) | **On-chain** (precompile) + off-chain | Chain-verifiable with a standard precompile |
| Signer is an **authorized** `tts_issuer` | **On-chain** (allowlist) + off-chain | Deny-by-default; a config the program owns |
| Signer is the issuer **this payer pinned** | **On-chain only** (immutable in the escrow) | Removes the admin from the custody path (§5.2 step 2b) |
| Payment amount/recipient/resource match the token | **On-chain** (digest equality) + off-chain | Reduces to a 32-byte constant-time compare |
| Token not expired (short TTL) | **On-chain** (slot/clock bound) + off-chain | Chain has a clock; enforce a max age |
| Scope ⊆ ceiling; delegation attenuation | **Off-chain only** | Requires chain-walking + policy; not chain-cheap |
| Revocation status | **Off-chain only** | Status-list lookup; would need an oracle |
| humanAnchor / zkDID proof | **Off-chain only** | ZK verification; separate, opt-in layer |
| JCS canonicalization of the request | **Off-chain only — NEVER on-chain** | §7: canonicalization mismatch = bypass |

**Composition principle.** The two enforcements are **conjunctive and
independent**: a payment settles only if *both* the off-chain PEP allowed it
(full 8 steps) *and* the on-chain program released it (signature + digest + issuer
+ freshness). Neither weakens the other; the on-chain layer is defense-in-depth
that removes the off-chain service from the *custody* trust path. The on-chain
layer must **never** be construed as sufficient authorization on its own — it does
not check scope, revocation, or the human anchor.

---

## 4. The commitment the chain checks

Define a fixed-layout, 32-byte **payment binding** computed by the issuer
off-chain at escrow-creation time and again referenced at release:

```
binding = SHA-256(
    DOMAIN_TAG_ESCROW ‖ 0x00 ‖          // domain separation, distinct from intent digest
    version:u8 ‖
    payer:Pubkey(32) ‖                  // funding account — makes the binding payer-specific
    mint:Pubkey(32) ‖                   // SPL mint (or a sentinel for native SOL)
    amount:u64_le ‖
    recipient:Pubkey(32) ‖              // merchant / payee
    resource_id:[u8;32] ‖               // hash of the x402 resource identifier
    nonce:[u8;32]                       // per-authorization nonce — makes it INSTANCE-unique
)
```

**Instance uniqueness is a security requirement, not a convenience.** `payer` and
`nonce` are included so that a single issuer attestation is valid for exactly one
escrow. Without them, every payment sharing `(mint, amount, recipient,
resource_id)` — the *normal* case for identical x402 orders — would share a
binding, and one attestation could release all of them (cross-escrow replay /
fund sweep). The issuer generates a fresh `nonce` per authorization and signs it
into the binding; the escrow stores it; the PDA seed includes the resulting
`binding`, so each authorization maps to exactly one escrow account.

This layout is **fixed-width and order-fixed** — there is no JSON, no map, no
optional field, nothing to canonicalize. Both the off-chain issuer and the
on-chain program compute `binding` from the *same primitive fields* via the
Solana `sha256` syscall / Go `crypto/sha256`, byte-for-byte identical by
construction.

The SPT-Txn token, when minted for an on-chain-enforced payment, MUST commit to
this `binding` value: the issuer sets `spt_txn_context_hash = hex(binding)` (or
carries `binding` in a dedicated claim `spt_escrow_binding`). The Ed25519
signature over the token thus covers `binding`.

---

## 5. Escrow lifecycle

Three custody instructions (plus the config/admin instructions in §5.4); all fail
closed.

### 5.1 `init_escrow`
Arguments, in Borsh order: `amount: u64`, `resource_id: [u8;32]`,
`nonce: [u8;32]`, `issuer: Pubkey`.

- **Payer** (the agent, or its funding authority) deposits `amount` of `mint`
  into an **Escrow PDA** derived from
  `["escrow", payer, recipient, binding]`.
- Stores in the Escrow account: `payer`, `recipient`, `mint`, `amount`,
  `issuer:Pubkey`, `binding:[u8;32]`, `nonce:[u8;32]`, `expiry_ts:i64`, `bump`,
  `vault_bump`.
- The program recomputes `binding` on-chain from the real account keys and these
  arguments. It is **not** an argument: a caller cannot store a binding that
  disagrees with the escrow it actually funded.
- **`issuer` is the payer's choice and is immutable once written.** It pins the
  single key whose attestation can ever release this escrow. Nothing — no admin
  instruction, no allowlist edit — can change it afterwards. This is what makes a
  compromised admin unable to reach funds that were already deposited (§5.2
  step 2b, THREAT-MODEL T9).
- `amount > 0`, else `InvalidAmount`.
- The pinned `issuer` must be on the allowlist **at deposit time**, else
  `IssuerNotAuthorized`. This is a usability guard, not the security control: a
  pin nobody has authorized would make the deposit unreleasable and strand the
  payer until expiry. The security control is the release-time pin check (§5.2
  step 2b), which the payer's choice here fixes forever.
- `expiry_ts = now + MAX_ESCROW_SECS` (900 s), on the on-chain `Clock`.
- **No release authorization is asserted here** — this is custody setup. The
  payer is not asserting the pinned issuer is trustworthy, only that it is the
  one they are willing to be released by.

> Ordering note for client authors: `resource_id`, `nonce` and `issuer` are three
> consecutive 32-byte arguments and Borsh carries no field names. A transposition
> is invisible to a length check and silent on chain — the escrow simply becomes
> releasable by a key the payer never chose. The reference client pins the order
> with a known-answer test (`escrow/anchor_test.go`).

### 5.2 `release_with_proof`  ← the enforcement instruction
Releases `amount` to `recipient` iff **all** hold (else the instruction aborts and
nothing moves):

1. **Ed25519 signature present & authentic.** The transaction includes an
   `Ed25519Program` verification instruction (§6). The program introspects it via
   the Instructions sysvar and confirms the precompile verified
   `(issuer_pubkey, token_msg, signature)`.
2. **Issuer authorized.** `issuer_pubkey` ∈ the program's `IssuerAllowlist`
   (`Config.issuers`, deny-by-default, maintained by the admin — §5.4). Unknown
   signer → **DENY** (`IssuerNotAuthorized`, 6102).
2b. **Issuer pinned.** `issuer_pubkey` equals `escrow.issuer` — the key *this
   payer* named at deposit — compared in constant time. Not the pinned key →
   **DENY** (`IssuerNotPinned`, 6108).

   Steps 2 and 2b are **ANDed, never substituted for one another.** The allowlist
   is a live, revocable, operator-held set; the pin is an immutable, payer-held
   choice that predates any later allowlist edit. An issuer added *after* a
   deposit satisfies 2 and fails 2b, which is precisely why an attacker holding
   the admin key cannot release a single existing escrow (THREAT-MODEL T9). The
   allowlist is still needed for the other direction: removing a compromised
   issuer stops every in-flight escrow pinned to it on the next block, which the
   pin alone could never do.
3. **Binding match.** The `binding` committed inside `token_msg` equals the
   escrow's stored `binding`, compared in **constant time**. Mismatch → **DENY**.
4. **Freshness.** The token's issued-at (carried in `token_msg`) is within
   `MAX_TOKEN_AGE_SLOTS` of the current slot, and the escrow is not past
   `expiry_slot`. Stale → **DENY**.
5. **Single use — structural.** A permanent **spent-marker PDA** `["spent",
   binding]` is created (`init`) during release and never closed. Replaying a
   captured attestation — even against an escrow re-initialized at the same PDA
   after a prior close — fails at the marker's `init` ("account already in use").
   Single use is therefore a property of the account system, not of close-on-
   release (which Solana account re-init can defeat). (adversarial-review Finding 1)

On success: transfer the vault's **live balance** (not the stored `amount`, so a
dust deposit into the vault cannot block `close_account` and trap the funds —
Finding 2) to `recipient`; close the vault and the escrow.

### 5.3 `refund_expired`
- After `expiry_slot`, **anyone** may trigger a refund of the escrowed `amount`
  back to `payer`, closing the escrow. This guarantees funds are never trapped if
  a release never comes (fail-closed for liveness, safe for custody).
- **Permissionless is deliberate, and is not a drain path.** The destination is
  pinned twice — `payer_ata.owner == escrow.payer` and `address = escrow.payer` —
  and is not an argument. The only thing an attacker achieves by calling it is
  paying their own gas to return the payer's money to the payer. Making it
  signer-gated would trade nothing for a liveness failure whenever the payer's
  key is lost or the agent is abandoned.

### 5.4 Config and admin instructions

None of these can move funds. They exist to maintain the issuer allowlist and to
keep the two operator roles — *who can change the code* and *who can change the
allowlist* — in different hands at runtime rather than by deploy convention.

**`init_config`** — one-time. Creates the `Config` PDA (`["config"]`) with an
**empty** issuer allowlist: deny-by-default, nobody is authorized until added.

- The **upgrade authority signs**, verified against the program's `ProgramData`
  account (`program_data.upgrade_authority_address == upgrade_authority.key()`),
  with `ProgramData` itself tied to this program via
  `program.programdata_address()` so a foreign one cannot be substituted. This is
  what makes the init front-run impossible: only the deployer can name the admin.
- The signer **does not become the admin.** `admin` is a separate, non-signing
  account key that is merely recorded, and the constraints reject the transaction
  if `admin == upgrade_authority` (`AdminIsUpgradeAuthority`) or if `admin` is the
  default pubkey (`InvalidAdmin`).
- Requires an **upgradeable** deployment. An immutable program (authority `None`)
  cannot run `init_config` at all — see THREAT-MODEL T9 on why burning the
  upgrade authority is the wrong hardening move here.

**`propose_admin(new_admin)`** — current admin signs (`has_one = admin`). Records
`Config.pending_admin`. Nothing else changes; the current admin keeps the role.
Rejects the default pubkey.

**`accept_admin`** — the nominee signs, and must equal `pending_admin`
(`NoPendingAdmin`). Only then does `admin` move and `pending_admin` clear. Two
steps, because the first is an assertion and the second is proof of possession —
a mistyped or hostile nomination has no on-chain effect. The upgrade-authority
separation is **re-checked here**
(`program_data.upgrade_authority_address != new_admin`), so a rotation months
after deployment cannot quietly collapse the two roles back into one key.

**`add_issuer(issuer)`** / **`remove_issuer(issuer)`** — admin signs. Add rejects
duplicates (`IssuerAlreadyPresent`) and a full list (`AllowlistFull`,
`MAX_ISSUERS`). Remove is idempotent. Both emit events
(`IssuerAdded`/`IssuerRemoved`, plus `AdminProposed`/`AdminChanged` on the
rotation path) for the transparency log — **detection, not the control.** The
control is that neither instruction can reach an escrow that already exists
(§5.2 step 2b).

The complete set of admin powers is therefore: edit the allowlist, and hand the
role over. That is a denial-of-service capability — the worst a compromised admin
achieves is that in-flight escrows expire and `refund_expired` returns every
payer's funds to the payer. It is not a custody capability.

---

## 6. How the Ed25519 check works on Solana (no custom crypto)

Solana verifies Ed25519 via the **native `Ed25519Program`
(`Ed25519SigVerify111...`) precompile**, not inside the BPF program. The pattern:

1. The client adds an `Ed25519Program` instruction to the same transaction,
   carrying `(issuer_pubkey, token_msg, signature)`.
2. If any tuple is invalid, the **runtime rejects the whole transaction** before
   our program runs — so an invalid signature can never reach release logic.
3. Our `release_with_proof` reads the **Instructions sysvar**
   (`sysvar::instructions`) and asserts that such an Ed25519 instruction exists in
   this transaction and that its `pubkey`, `message`, and `signature` are the ones
   we require (issuer ∈ allowlist; message = the `token_msg` we parse `binding`
   and `iat` from). This introspection is mandatory: **presence of the precompile
   instruction is only meaningful if we bind its arguments to our checks** — a
   naïve program that assumes "a precompile ran" without verifying *which* pubkey
   and *which* message is a known bypass (§7.2).

No signature math runs in our program. `crypto` = the audited precompile only.

---

## 7. Prohibited anti-patterns (each is an automatic reject)

**7.1 Canonicalizing on-chain.** Do not parse JSON, sort map keys, or re-serialize
a request inside the program. All chain checks operate on the fixed-width
`binding` (§4). If a change ever seems to require JSON on-chain, stop — the design
is wrong.

**7.2 Trusting "a precompile ran."** Do not release just because an Ed25519
instruction is present. Bind its `pubkey` (allowlist) and `message` (our
`token_msg`) explicitly, read from the Instructions sysvar.

**7.3 Fail-open on missing data.** Missing sysvar, unparseable `token_msg`,
allowlist not initialized, arithmetic overflow → **DENY / abort**, never proceed.

**7.4 Widening on refund.** `refund_expired` returns funds only to the original
`payer`, only after `expiry_slot`. No parameter may redirect a refund.

**7.5 Custom comparison.** Digest equality uses a constant-time compare, never a
short-circuiting `==` on secret-adjacent bytes.

---

## 8. Fail-closed decision classes

Mirror the off-chain verifier's distinction so operators can tell an attack from
an outage:

- `DENY_VIOLATION` — signature invalid, issuer not allowlisted, binding mismatch,
  stale token. (An attack or a misissued token.)
- `DENY_UNAVAILABLE` — required sysvar/account missing or uninitialized. (An
  environment/config fault.)

Both refuse to release. The instruction returns a distinct custom error per class.

---

## 9. What this buys, honestly

- **Trustless enforcement of custody:** funds move only with a valid, authorized,
  fresh, correctly-bound issuer signature — verifiable by anyone, no off-chain
  service in the custody path.
- **Not** a full authorization decision: scope, revocation, delegation, and the
  human anchor remain off-chain. The on-chain layer is deliberately a *binding +
  signature + freshness* gate, and the spec says so plainly so no reviewer or
  auditor over-reads it.

This is the honest, defensible scope for a hackathon "Best Trustless Agent"
submission and for later due diligence.
