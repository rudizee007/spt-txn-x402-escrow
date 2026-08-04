//! Fail-closed error set. Every DENY carries a decision class so operators can
//! tell an attack (VIOLATION) from an outage/config fault (UNAVAILABLE) —
//! mirroring the off-chain verifier (SPEC §8).

use anchor_lang::prelude::*;

#[error_code]
pub enum EscrowError {
    // ── DENY_VIOLATION: an attack, or a mis-issued token ────────────────────
    #[msg("VIOLATION: no Ed25519 verification instruction bound to this release")]
    MissingEd25519Instruction = 100,
    #[msg("VIOLATION: Ed25519 instruction references data outside its own bounds")]
    MalformedEd25519Instruction,
    #[msg("VIOLATION: signer is not an authorized SPT-Txn issuer")]
    IssuerNotAuthorized,
    #[msg("VIOLATION: attestation message is malformed or wrong length")]
    MalformedAttestation,
    #[msg("VIOLATION: attestation layout version is not supported")]
    UnsupportedVersion,
    #[msg("VIOLATION: bound payment digest does not match this escrow")]
    BindingMismatch,
    #[msg("VIOLATION: attestation is stale or not yet valid")]
    AttestationExpired,
    #[msg("VIOLATION: escrow has passed its expiry; release is no longer allowed")]
    EscrowExpired,
    #[msg("VIOLATION: attestation issuer is not the issuer pinned to this escrow")]
    IssuerNotPinned,

    // ── DENY_UNAVAILABLE: environment/config fault, not an authorization result
    #[msg("UNAVAILABLE: issuer allowlist is not initialized")]
    AllowlistUninitialized = 200,
    #[msg("UNAVAILABLE: instructions sysvar missing or unreadable")]
    InstructionsSysvarUnavailable,

    // ── Custody / arithmetic safety ─────────────────────────────────────────
    #[msg("checked arithmetic overflow")]
    MathOverflow = 300,
    #[msg("issuer allowlist is full")]
    AllowlistFull,
    #[msg("issuer already present in allowlist")]
    IssuerAlreadyPresent,
    #[msg("refund is only permitted after escrow expiry")]
    RefundBeforeExpiry,
    #[msg("VIOLATION: escrow amount must be greater than zero")]
    InvalidAmount,
    #[msg("VIOLATION: init_config signer is not the program upgrade authority")]
    NotUpgradeAuthority,
    #[msg("admin must not be the program upgrade authority: the roles are held separately")]
    AdminIsUpgradeAuthority,
    #[msg("admin must not be the default pubkey")]
    InvalidAdmin,
    #[msg("no admin handover is pending, or the signer is not the pending admin")]
    NoPendingAdmin,
}
