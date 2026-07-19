//! Fixed constants and byte layouts. Everything here is part of the security
//! contract with the off-chain issuer — changing any tag, width, or order is a
//! breaking change that must be mirrored in the Go issuer AND re-fuzzed against
//! shared vectors (docs/THREAT-MODEL.md T1).

use anchor_lang::prelude::*;

/// Native Ed25519 signature-verification precompile. Signatures are verified by
/// this program (the runtime), NEVER inside our BPF code (SPEC §6, no custom crypto).
pub const ED25519_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Ed25519SigVerify111111111111111111111111111");

/// Native Instructions sysvar — the read-only account we introspect to find the
/// Ed25519 precompile result (SPEC §6).
pub const INSTRUCTIONS_SYSVAR_ID: Pubkey =
    Pubkey::from_str_const("Sysvar1nstructions1111111111111111111111111");

/// Domain tag for the escrow payment-binding hash (SPEC §4). Distinct from every
/// other SHA-256 use so a binding can never collide with an intent digest.
pub const DOMAIN_TAG_ESCROW: &[u8] = b"spt-txn/x402-escrow-binding/v1";

/// Domain tag for the compact, fixed-layout on-chain attestation the issuer signs
/// (SPEC §6). This is NOT the JWT — it is a parallel fixed-width message dedicated
/// to on-chain enforcement, so the program never parses JSON/base64 (SPEC §7.1).
pub const DOMAIN_TAG_ATTEST: &[u8] = b"spt-txn/x402-onchain-attest/v1";

/// Current binding/attestation layout version.
pub const LAYOUT_VERSION: u8 = 1;

// ── token_msg (the issuer-signed attestation) fixed layout ──────────────────
// [0 .. T)        DOMAIN_TAG_ATTEST                    (T bytes)
// [T]             version: u8                          (1 byte)
// [T+1 .. T+33)   binding: [u8; 32]                    (32 bytes)
// [T+33 .. T+41)  iat: i64 little-endian (unix secs)   (8 bytes)
pub const ATTEST_TAG_LEN: usize = DOMAIN_TAG_ATTEST.len();
pub const ATTEST_OFF_VERSION: usize = ATTEST_TAG_LEN;
pub const ATTEST_OFF_BINDING: usize = ATTEST_TAG_LEN + 1;
pub const ATTEST_OFF_IAT: usize = ATTEST_TAG_LEN + 1 + 32;
pub const ATTEST_MSG_LEN: usize = ATTEST_TAG_LEN + 1 + 32 + 8;

/// Max age of an issuer attestation, in seconds. SPT-Txn tokens are short-lived;
/// the on-chain path enforces its own bound so a captured attestation cannot be
/// replayed indefinitely (SPEC §5.2 step 4, THREAT-MODEL T7).
pub const MAX_TOKEN_AGE_SECS: i64 = 120;

/// Allowed clock skew (issuer clock ahead of the validator clock).
pub const MAX_CLOCK_SKEW_SECS: i64 = 30;

/// Max escrow lifetime before `refund_expired` is permitted (SPEC §5.3).
pub const MAX_ESCROW_SECS: i64 = 900; // 15 minutes

/// Upper bound on authorized issuers held in the Config allowlist.
pub const MAX_ISSUERS: usize = 16;

// PDA seeds.
pub const SEED_CONFIG: &[u8] = b"config";
pub const SEED_ESCROW: &[u8] = b"escrow";
pub const SEED_VAULT: &[u8] = b"vault";
/// Permanent single-use marker per binding (adversarial-review Finding 1).
pub const SEED_SPENT: &[u8] = b"spent";
