//! On-chain state. Deny-by-default: `Config.issuers` starts empty and an empty
//! allowlist authorizes nobody (SPEC §7.3, THREAT-MODEL T3).

use anchor_lang::prelude::*;
use crate::constants::MAX_ISSUERS;

/// Program configuration: the admin authority and the issuer allowlist. One per
/// program deployment, at PDA [SEED_CONFIG].
#[account]
pub struct Config {
    /// Admin authority permitted to add/remove issuers — and NOTHING else. It can
    /// reach no vault and no escrow, and it cannot cause a release: every release
    /// is additionally gated on the issuer pinned into the escrow at deposit
    /// (see `Escrow.issuer`). Enforced distinct from the program upgrade authority
    /// at `init_config` and again at `accept_admin`, so the separation is a runtime
    /// constraint rather than a deployment convention (THREAT-MODEL T9).
    pub admin: Pubkey,
    /// Nominee in a two-step admin handover. Set by `propose_admin` (current admin
    /// signs) and cleared by `accept_admin` (the nominee signs). A single-step
    /// transfer to a typo'd or uncontrolled key would strand the role forever;
    /// requiring the nominee to sign proves the key exists and is held.
    /// `Pubkey::default()` means no handover is pending.
    pub pending_admin: Pubkey,
    /// Authorized SPT-Txn issuer Ed25519 public keys. A release is only honored if
    /// the precompile-verified signer is in this set. Empty = allow nobody.
    pub issuers: Vec<Pubkey>,
    pub bump: u8,
}

impl Config {
    // 8 disc + 32 admin + 32 pending_admin + 4 vec len + (32 * MAX_ISSUERS) + 1 bump
    pub const MAX_SIZE: usize = 8 + 32 + 32 + 4 + (32 * MAX_ISSUERS) + 1;

    /// Constant-time-ish membership check over a small fixed set. The set is
    /// public (issuer pubkeys are not secret), so ordinary equality is acceptable
    /// here; the constant-time requirement applies to the *binding* compare
    /// (SPEC §7.5), not to public-key set membership.
    pub fn is_authorized(&self, signer: &Pubkey) -> bool {
        self.issuers.iter().any(|k| k == signer)
    }
}

/// A single escrowed x402 payment, at PDA [SEED_ESCROW, payer, recipient, binding].
/// `binding` is computed on-chain at init from the real escrow parameters, so the
/// stored value is trustworthy and equals what the issuer signs off-chain.
#[account]
pub struct Escrow {
    pub payer: Pubkey,
    pub recipient: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    /// The ONLY issuer whose attestation can release this escrow, chosen by the
    /// payer at deposit and immutable thereafter. The allowlist is checked *as
    /// well*, never instead: pinning means an issuer added after this deposit
    /// cannot touch it, and retaining the allowlist means a compromised issuer can
    /// still be revoked mid-flight. Together they reduce a fully compromised admin
    /// to a denial-of-service role whose worst outcome is that payers get refunded
    /// at expiry — it cannot cause one unauthorized release (THREAT-MODEL T9).
    pub issuer: Pubkey,
    /// SHA-256 payment binding (SPEC §4), computed on-chain in `init_escrow`.
    /// Instance-unique: incorporates `payer` and `nonce`.
    pub binding: [u8; 32],
    /// Per-authorization nonce that makes `binding` unique to this escrow
    /// instance (adversarial-review finding; THREAT-MODEL T4).
    pub nonce: [u8; 32],
    /// Unix timestamp after which `refund_expired` is allowed and release is not.
    pub expiry_ts: i64,
    pub bump: u8,
    pub vault_bump: u8,
}

impl Escrow {
    // 8 disc + 32*3 (payer,recipient,mint) + 8 (amount) + 32 (issuer) + 32 (binding)
    //        + 32 (nonce) + 8 (expiry) + 1 (bump) + 1 (vault_bump)
    //
    // Field ORDER is the wire format for every off-chain decoder (cmd/escrowdevnet,
    // the TS client). `issuer` sits between `amount` and `binding`; a decoder that
    // still reads the old layout will silently mis-parse `binding` onwards.
    pub const MAX_SIZE: usize = 8 + (32 * 3) + 8 + 32 + 32 + 32 + 8 + 1 + 1;
}

/// Permanent single-use marker at PDA [SEED_SPENT, binding]. Created on release,
/// NEVER closed. A replayed release re-derives the same PDA and fails at `init`,
/// so single-use is a property of the account system — not of close-on-release,
/// which Solana account re-initialization can defeat (adversarial-review Finding 1).
#[account]
pub struct SpentMarker {}

impl SpentMarker {
    pub const MAX_SIZE: usize = 8; // discriminator only
}
