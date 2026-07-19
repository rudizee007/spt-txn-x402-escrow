//! ⚠ SECURITY-CRITICAL — the enforcement core. Do NOT ship to mainnet before the
//! adversarial "assume this contains a bypass, find it" review and the property
//! + fuzz tests in docs/THREAT-MODEL.md. This file verifies NO signatures itself:
//! it introspects the result of the native Ed25519 precompile and binds that
//! result to our escrow (SPEC §6). No JSON, no canonicalization (SPEC §7.1).

use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};
use crate::constants::*;
use crate::errors::EscrowError;

/// Compute the fixed-width payment binding (SPEC §4). Identical bytes to the Go
/// issuer by construction — no ordering, no optional fields, nothing to
/// canonicalize.
///
/// The binding is **instance-unique**: it includes `payer` and a per-authorization
/// `nonce` so that a single issuer attestation is valid for exactly ONE escrow.
/// Omitting these (an earlier version did) let one attestation release every
/// escrow that shared `(mint, amount, recipient, resource_id)` — a cross-escrow
/// replay / fund-sweep (adversarial-review finding; THREAT-MODEL T4).
/// `resource_id` is a 32-byte hash of the x402 resource identifier.
pub fn compute_binding(
    payer: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    recipient: &Pubkey,
    resource_id: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG_ESCROW);
    h.update([0u8]);
    h.update([LAYOUT_VERSION]);
    h.update(payer.as_ref());
    h.update(mint.as_ref());
    h.update(amount.to_le_bytes());
    h.update(recipient.as_ref());
    h.update(resource_id);
    h.update(nonce);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Constant-time 32-byte equality (SPEC §7.5). Never short-circuits.
#[inline(never)]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// The verified result of the issuer's on-chain attestation.
pub struct Attestation {
    pub issuer: Pubkey,
    pub binding: [u8; 32],
    pub iat: i64,
}

#[inline(always)]
fn read_u16_le(data: &[u8], at: usize) -> Result<u16> {
    let end = at.checked_add(2).ok_or(EscrowError::MalformedEd25519Instruction)?;
    let slice = data
        .get(at..end)
        .ok_or(EscrowError::MalformedEd25519Instruction)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

/// Scan the transaction's earlier instructions for the native Ed25519 precompile
/// instruction, extract the (pubkey, message) IT verified, and parse the message
/// as our fixed-layout attestation. Any inconsistency fails closed.
///
/// Security notes (THREAT-MODEL T2):
///  - The runtime has ALREADY verified the signature if this instruction is
///    present; an invalid signature would have aborted the whole transaction.
///  - But "a precompile ran" is meaningless unless we bind WHICH pubkey and WHICH
///    message. We extract both from the precompile instruction's own data and
///    return them; the caller checks the pubkey against the allowlist and the
///    binding against the escrow. We REQUIRE the offsets to reference the ed25519
///    instruction itself (index == u16::MAX); a message sourced from another
///    instruction is rejected as out of scope.
pub fn find_and_verify_attestation(ix_sysvar: &AccountInfo) -> Result<Attestation> {
    let current = load_current_index_checked(ix_sysvar)
        .map_err(|_| EscrowError::InstructionsSysvarUnavailable)?;

    // The ed25519 instruction must precede ours in the same transaction.
    for i in 0..current {
        let ix = match load_instruction_at_checked(i as usize, ix_sysvar) {
            Ok(ix) => ix,
            Err(_) => continue,
        };
        // Compare by bytes: the sysvar crate's Pubkey may be a different crate
        // version than anchor's, but the 32-byte value is identical.
        if ix.program_id.to_bytes() != ED25519_PROGRAM_ID.to_bytes() {
            continue;
        }
        return parse_ed25519_instruction(&ix.data);
    }
    Err(EscrowError::MissingEd25519Instruction.into())
}

/// Parse a single-signature Ed25519 precompile instruction's data and the fixed
/// attestation message it covers. Layout of the precompile data:
///   [0]=num_signatures u8, [1]=padding u8, then a 14-byte offsets struct:
///   sig_off u16, sig_ix u16, pk_off u16, pk_ix u16, msg_off u16, msg_size u16, msg_ix u16
fn parse_ed25519_instruction(data: &[u8]) -> Result<Attestation> {
    // Header.
    let num_sigs = *data.get(0).ok_or(EscrowError::MalformedEd25519Instruction)?;
    if num_sigs != 1 {
        // Exactly one signature is expected for a release. Reject batches to keep
        // the introspection total and unambiguous.
        return Err(EscrowError::MalformedEd25519Instruction.into());
    }

    // Offsets struct begins at byte 2.
    const B: usize = 2;
    let pk_off = read_u16_le(data, B + 4)? as usize;
    let pk_ix = read_u16_le(data, B + 6)?;
    let msg_off = read_u16_le(data, B + 8)? as usize;
    let msg_size = read_u16_le(data, B + 10)? as usize;
    let msg_ix = read_u16_le(data, B + 12)?;

    // The pubkey and message must live in THIS instruction (u16::MAX sentinel).
    // Anything else is out of scope and denied (THREAT-MODEL T2).
    if pk_ix != u16::MAX || msg_ix != u16::MAX {
        return Err(EscrowError::MalformedEd25519Instruction.into());
    }

    // Extract the verified public key (32 bytes).
    let pk_end = pk_off
        .checked_add(32)
        .ok_or(EscrowError::MalformedEd25519Instruction)?;
    let pk_bytes = data
        .get(pk_off..pk_end)
        .ok_or(EscrowError::MalformedEd25519Instruction)?;
    let issuer = Pubkey::try_from(pk_bytes)
        .map_err(|_| EscrowError::MalformedEd25519Instruction)?;

    // Extract the verified message and parse the fixed attestation layout.
    if msg_size != ATTEST_MSG_LEN {
        return Err(EscrowError::MalformedAttestation.into());
    }
    let msg_end = msg_off
        .checked_add(msg_size)
        .ok_or(EscrowError::MalformedEd25519Instruction)?;
    let msg = data
        .get(msg_off..msg_end)
        .ok_or(EscrowError::MalformedEd25519Instruction)?;

    // Domain tag must match exactly (no partial match).
    if &msg[0..ATTEST_TAG_LEN] != DOMAIN_TAG_ATTEST {
        return Err(EscrowError::MalformedAttestation.into());
    }
    // Version.
    if msg[ATTEST_OFF_VERSION] != LAYOUT_VERSION {
        return Err(EscrowError::UnsupportedVersion.into());
    }
    // Binding (32 bytes).
    let mut binding = [0u8; 32];
    binding.copy_from_slice(&msg[ATTEST_OFF_BINDING..ATTEST_OFF_BINDING + 32]);
    // iat (i64 LE).
    let mut iat_bytes = [0u8; 8];
    iat_bytes.copy_from_slice(&msg[ATTEST_OFF_IAT..ATTEST_OFF_IAT + 8]);
    let iat = i64::from_le_bytes(iat_bytes);

    Ok(Attestation { issuer, binding, iat })
}

/// Enforce attestation freshness against the on-chain clock (SPEC §5.2 step 4).
pub fn check_freshness(iat: i64, now: i64) -> Result<()> {
    // Not too old.
    let age = now.checked_sub(iat).ok_or(EscrowError::MathOverflow)?;
    if age > MAX_TOKEN_AGE_SECS {
        return Err(EscrowError::AttestationExpired.into());
    }
    // Not implausibly future-dated (bounded clock skew).
    if age < -MAX_CLOCK_SKEW_SECS {
        return Err(EscrowError::AttestationExpired.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_freshness, compute_binding, ct_eq_32, parse_ed25519_instruction};
    use crate::constants::*;
    use anchor_lang::prelude::Pubkey;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }
    fn hex_lower(b: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for x in b {
            s.push_str(&format!("{:02x}", x));
        }
        s
    }

    /// Cross-language known-answer test. The Go issuer (`go run . selftest`) and an
    /// independent Python computation both produce this exact binding for the same
    /// inputs. A divergence between issuer and verifier here is a latent
    /// authorization bypass (THREAT-MODEL T1).
    #[test]
    fn binding_known_answer_vector() {
        let b = compute_binding(&pk(0x11), &pk(0x22), 1_000_000, &pk(0x33), &[0x44; 32], &[0x55; 32]);
        assert_eq!(
            hex_lower(&b),
            "3a08cc7c2ac1c8061262c2c901b95e77fae75fc918955acceb4d4bd17b8444a4"
        );
    }

    /// The binding must be instance-unique in every field — this is the regression
    /// for the cross-escrow replay Critical (payer, nonce) and general soundness.
    #[test]
    fn binding_is_instance_unique() {
        let base = compute_binding(&pk(1), &pk(0x22), 100, &pk(0x33), &[0x44; 32], &[0x55; 32]);
        // determinism
        assert_eq!(base, compute_binding(&pk(1), &pk(0x22), 100, &pk(0x33), &[0x44; 32], &[0x55; 32]));
        // each input flips the binding
        assert_ne!(base, compute_binding(&pk(2), &pk(0x22), 100, &pk(0x33), &[0x44; 32], &[0x55; 32])); // payer
        assert_ne!(base, compute_binding(&pk(1), &pk(0x23), 100, &pk(0x33), &[0x44; 32], &[0x55; 32])); // mint
        assert_ne!(base, compute_binding(&pk(1), &pk(0x22), 101, &pk(0x33), &[0x44; 32], &[0x55; 32])); // amount
        assert_ne!(base, compute_binding(&pk(1), &pk(0x22), 100, &pk(0x34), &[0x44; 32], &[0x55; 32])); // recipient
        assert_ne!(base, compute_binding(&pk(1), &pk(0x22), 100, &pk(0x33), &[0x45; 32], &[0x55; 32])); // resource
        assert_ne!(base, compute_binding(&pk(1), &pk(0x22), 100, &pk(0x33), &[0x44; 32], &[0x56; 32])); // nonce
    }

    #[test]
    fn ct_eq_32_correct() {
        let a = [7u8; 32];
        assert!(ct_eq_32(&a, &[7u8; 32]));
        let mut b = [7u8; 32];
        b[31] ^= 1;
        assert!(!ct_eq_32(&a, &b));
        let mut c = [7u8; 32];
        c[0] ^= 0x80;
        assert!(!ct_eq_32(&a, &c));
    }

    #[test]
    fn freshness_bounds() {
        assert!(check_freshness(1000, 1000).is_ok());
        assert!(check_freshness(1000, 1000 + MAX_TOKEN_AGE_SECS).is_ok());
        assert!(check_freshness(1000, 1000 + MAX_TOKEN_AGE_SECS + 1).is_err()); // too old
        assert!(check_freshness(1000, 1000 - MAX_CLOCK_SKEW_SECS).is_ok());
        assert!(check_freshness(1000, 1000 - MAX_CLOCK_SKEW_SECS - 1).is_err()); // future beyond skew
    }

    // ---- Ed25519 precompile instruction parser — negative matrix (THREAT-MODEL T2) ----

    fn valid_msg() -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(DOMAIN_TAG_ATTEST);
        m.push(LAYOUT_VERSION);
        m.extend_from_slice(&[0x5A; 32]); // binding
        m.extend_from_slice(&1_700_000_000i64.to_le_bytes()); // iat
        m
    }

    // Well-formed single-signature ed25519 instruction data for `msg`.
    fn good_ix(msg: &[u8]) -> Vec<u8> {
        let pk_bytes = [0xABu8; 32];
        let sig = [0xCDu8; 64];
        let mut d = vec![1u8, 0u8]; // num_signatures=1, padding
        for v in [48u16, 0xFFFF, 16u16, 0xFFFF, 112u16, msg.len() as u16, 0xFFFF] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(&pk_bytes);
        d.extend_from_slice(&sig);
        d.extend_from_slice(msg);
        d
    }

    #[test]
    fn parse_accepts_wellformed() {
        let att = parse_ed25519_instruction(&good_ix(&valid_msg())).unwrap();
        assert_eq!(att.issuer.to_bytes(), [0xAB; 32]);
        assert_eq!(att.binding, [0x5A; 32]);
        assert_eq!(att.iat, 1_700_000_000);
    }

    #[test]
    fn parse_rejects_bad_inputs() {
        let m = valid_msg();
        assert!(parse_ed25519_instruction(&[]).is_err()); // empty
        assert!(parse_ed25519_instruction(&[1, 0, 0, 0]).is_err()); // truncated offsets

        let mut d = good_ix(&m); d[0] = 2; assert!(parse_ed25519_instruction(&d).is_err()); // num_sigs=2
        let mut d = good_ix(&m); d[0] = 0; assert!(parse_ed25519_instruction(&d).is_err()); // num_sigs=0
        let mut d = good_ix(&m); d[8] = 0; d[9] = 0; assert!(parse_ed25519_instruction(&d).is_err()); // pk_ix != MAX
        let mut d = good_ix(&m); d[14] = 0; d[15] = 0; assert!(parse_ed25519_instruction(&d).is_err()); // msg_ix != MAX
        let mut d = good_ix(&m); d[10] = 0xFF; d[11] = 0xFF; assert!(parse_ed25519_instruction(&d).is_err()); // msg_off OOB

        assert!(parse_ed25519_instruction(&good_ix(&m[..m.len() - 1])).is_err()); // msg_size != ATTEST_MSG_LEN

        let mut wrong_tag = valid_msg(); wrong_tag[0] ^= 1;
        assert!(parse_ed25519_instruction(&good_ix(&wrong_tag)).is_err()); // bad domain tag

        let mut wrong_ver = valid_msg(); wrong_ver[DOMAIN_TAG_ATTEST.len()] = 0xFF;
        assert!(parse_ed25519_instruction(&good_ix(&wrong_ver)).is_err()); // bad version
    }
}
