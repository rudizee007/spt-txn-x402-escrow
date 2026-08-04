//! litesvm end-to-end integration test. Proves at runtime what the unit tests
//! prove in logic: the full escrow lifecycle works, the Ed25519 sysvar
//! introspection finds and binds the attestation, a replayed attestation is
//! rejected by the permanent spent-marker (adversarial-review Finding 1), and a
//! fully compromised admin cannot cause a release (THREAT-MODEL T9).
//!
//! Requires the built program: run `cargo build-sbf` first, then `cargo test`.
//! SPL token accounts are injected directly (set_account) to keep the harness
//! dependency-light; the program still creates the vault via a real CPI.

use {
    anchor_lang::{
        prelude::Pubkey,
        solana_program::{instruction::Instruction, system_program},
        InstructionData, ToAccountMetas,
    },
    litesvm::LiteSVM,
    solana_account::Account,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    spt_x402_escrow::{constants::*, errors::EscrowError, verify::compute_binding},
};

const SPL_TOKEN_ID: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const RENT_SYSVAR_ID: Pubkey = Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
const BPF_LOADER_UPGRADEABLE_ID: Pubkey = Pubkey::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const AMOUNT: u64 = 1_000_000;

// ── SPL account byte layouts (Token program) ────────────────────────────────
fn spl_mint_data(mint_authority: &Pubkey, supply: u64, decimals: u8) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[0..4].copy_from_slice(&[1, 0, 0, 0]); // COption::Some(mint_authority)
    d[4..36].copy_from_slice(mint_authority.as_ref());
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[44] = decimals;
    d[45] = 1; // is_initialized
    d
}

fn spl_token_account_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // AccountState::Initialized
    d
}

fn inject(svm: &mut LiteSVM, key: &Pubkey, owner: &Pubkey, data: Vec<u8>) {
    svm.set_account(
        *key,
        Account { lamports: 10_000_000, data, owner: *owner, executable: false, rent_epoch: 0 },
    )
    .unwrap();
}

fn token_amount(svm: &LiteSVM, ata: &Pubkey) -> u64 {
    let acc = svm.get_account(ata).unwrap();
    u64::from_le_bytes(acc.data[64..72].try_into().unwrap())
}

// ── attestation helpers ─────────────────────────────────────────────────────
fn build_token_msg(binding: &[u8; 32], iat: i64) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOMAIN_TAG_ATTEST);
    m.push(LAYOUT_VERSION);
    m.extend_from_slice(binding);
    m.extend_from_slice(&iat.to_le_bytes());
    m
}

fn build_ed25519_ix(issuer_pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> Instruction {
    let mut d = vec![1u8, 0u8]; // num_signatures=1, padding
    for v in [48u16, 0xFFFF, 16u16, 0xFFFF, 112u16, msg.len() as u16, 0xFFFF] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(issuer_pk);
    d.extend_from_slice(sig);
    d.extend_from_slice(msg);
    Instruction { program_id: ED25519_PROGRAM_ID, accounts: vec![], data: d }
}

fn send(svm: &mut LiteSVM, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) -> bool {
    // Fresh blockhash per tx → unique signature. Without this, the byte-identical
    // re-init (and replay release) would be rejected as AlreadyProcessed instead
    // of actually executing and hitting the spent-marker.
    svm.expire_blockhash();
    let bh = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &bh);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), signers).unwrap();
    match svm.send_transaction(tx) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("  TX ERROR: {:?}", e.err);
            for l in &e.meta.logs {
                eprintln!("  LOG: {}", l);
            }
            false
        }
    }
}

/// Assert a transaction failed *for the stated reason*. A bare `!send(..)` also
/// passes when the tx failed on a missing account or a stale blockhash — which is
/// how a negative test quietly stops testing the thing it is named after.
fn send_expecting(
    svm: &mut LiteSVM,
    ixs: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
    err: EscrowError,
) -> bool {
    let name = format!("{:?}", err);
    let code = err as u32 + anchor_lang::error::ERROR_CODE_OFFSET;

    svm.expire_blockhash();
    let bh = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &bh);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), signers).unwrap();
    match svm.send_transaction(tx) {
        Ok(_) => {
            eprintln!("  EXPECTED FAILURE {} ({}), GOT SUCCESS", name, code);
            false
        }
        Err(e) => {
            // The error struct prints the code in decimal; the program logs print it
            // in hex. Accept either so this does not break on a formatting change.
            let dec = format!("Custom({})", code);
            let hex = format!("0x{:x}", code);
            let hit = format!("{:?}", e.err).contains(&dec)
                || e.meta.logs.iter().any(|l| l.contains(&hex) || l.contains(&dec));
            if !hit {
                eprintln!("  WRONG FAILURE: wanted {} ({} / {}), got {:?}", name, dec, hex, e.err);
                for l in &e.meta.logs {
                    eprintln!("  LOG: {}", l);
                }
            }
            hit
        }
    }
}

// ── shared fixture ──────────────────────────────────────────────────────────

/// Everything a test needs. `upgrade_authority` and `admin` are deliberately
/// distinct keys — the program now refuses to let one key hold both roles.
struct Fx {
    svm: LiteSVM,
    program_id: Pubkey,
    upgrade_authority: Keypair,
    admin: Keypair,
    payer: Keypair,
    releaser: Keypair,
    issuer: Keypair,
    recipient: Pubkey,
    mint: Pubkey,
    payer_ata: Pubkey,
    recipient_ata: Pubkey,
    config: Pubkey,
    program_data: Pubkey,
}

/// Loads the program, funds the keys, injects SPL accounts, and patches the
/// ProgramData record so `upgrade_authority` really is the upgrade authority.
/// Does NOT run init_config — the init_config tests need it unset.
fn base() -> Fx {
    let program_id = spt_x402_escrow::id();
    let mut svm = LiteSVM::new();
    let bytes = include_bytes!(concat!(env!("CARGO_TARGET_TMPDIR"), "/../deploy/spt_x402_escrow.so"));
    svm.add_program(program_id, bytes).unwrap();

    let upgrade_authority = Keypair::new();
    let admin = Keypair::new();
    let payer = Keypair::new();
    let releaser = Keypair::new();
    let issuer = Keypair::new(); // the SPT-Txn attestation signer
    let recipient = Keypair::new().pubkey();
    let mint = Keypair::new().pubkey();
    let payer_ata = Keypair::new().pubkey();
    let recipient_ata = Keypair::new().pubkey();

    for kp in [&upgrade_authority, &admin, &payer, &releaser] {
        svm.airdrop(&kp.pubkey(), 1_000_000_000).unwrap();
    }
    inject(&mut svm, &mint, &SPL_TOKEN_ID, spl_mint_data(&admin.pubkey(), AMOUNT, 0));
    inject(&mut svm, &payer_ata, &SPL_TOKEN_ID, spl_token_account_data(&mint, &payer.pubkey(), AMOUNT));
    inject(&mut svm, &recipient_ata, &SPL_TOKEN_ID, spl_token_account_data(&mint, &recipient, 0));

    let (config, _) = Pubkey::find_program_address(&[SEED_CONFIG], &program_id);

    // Finding 3: litesvm loads the program with upgrade_authority = None, so patch
    // the ProgramData metadata: [0..4]=variant(3=ProgramData), [4..12]=slot,
    // [12]=Option tag(1=Some), [13..45]=authority pubkey.
    let (program_data, _) = Pubkey::find_program_address(&[program_id.as_ref()], &BPF_LOADER_UPGRADEABLE_ID);
    let mut pd = svm.get_account(&program_data).unwrap();
    pd.data[0..4].copy_from_slice(&3u32.to_le_bytes());
    pd.data[12] = 1;
    pd.data[13..45].copy_from_slice(upgrade_authority.pubkey().as_ref());
    svm.set_account(program_data, pd).unwrap();

    Fx {
        svm, program_id, upgrade_authority, admin, payer, releaser, issuer,
        recipient, mint, payer_ata, recipient_ata, config, program_data,
    }
}

/// base() + init_config(admin) + add_issuer(issuer). The common starting point.
fn bootstrapped() -> Fx {
    let mut fx = base();
    let ix = fx.init_config_ix(fx.admin.pubkey());
    assert!(
        send(&mut fx.svm, &[ix], &fx.upgrade_authority, &[&fx.upgrade_authority]),
        "init_config failed"
    );
    let ix = fx.add_issuer_ix(fx.admin.pubkey(), fx.issuer.pubkey());
    assert!(send(&mut fx.svm, &[ix], &fx.admin, &[&fx.admin]), "add_issuer failed");
    fx
}

impl Fx {
    /// init_config: the UPGRADE AUTHORITY signs (blocking the front-run) and names
    /// a separate `admin`. The admin never signs here.
    fn init_config_ix(&self, admin: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            self.program_id,
            &spt_x402_escrow::instruction::InitConfig {}.data(),
            spt_x402_escrow::accounts::InitConfig {
                config: self.config,
                upgrade_authority: self.upgrade_authority.pubkey(),
                admin,
                program: self.program_id,
                program_data: self.program_data,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    }

    fn add_issuer_ix(&self, admin: Pubkey, issuer: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            self.program_id,
            &spt_x402_escrow::instruction::AddIssuer { issuer }.data(),
            spt_x402_escrow::accounts::AdminConfig { config: self.config, admin }.to_account_metas(None),
        )
    }

    fn remove_issuer_ix(&self, admin: Pubkey, issuer: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            self.program_id,
            &spt_x402_escrow::instruction::RemoveIssuer { issuer }.data(),
            spt_x402_escrow::accounts::AdminConfig { config: self.config, admin }.to_account_metas(None),
        )
    }

    fn propose_admin_ix(&self, admin: Pubkey, new_admin: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            self.program_id,
            &spt_x402_escrow::instruction::ProposeAdmin { new_admin }.data(),
            spt_x402_escrow::accounts::AdminConfig { config: self.config, admin }.to_account_metas(None),
        )
    }

    fn accept_admin_ix(&self, new_admin: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            self.program_id,
            &spt_x402_escrow::instruction::AcceptAdmin {}.data(),
            spt_x402_escrow::accounts::AcceptAdmin {
                config: self.config,
                new_admin,
                program: self.program_id,
                program_data: self.program_data,
            }
            .to_account_metas(None),
        )
    }

    /// `issuer` here is the PIN written into the escrow — the only key whose
    /// attestation can ever release it.
    fn init_escrow_ix(
        &self,
        issuer: Pubkey,
        resource_id: [u8; 32],
        nonce: [u8; 32],
        escrow: Pubkey,
        vault: Pubkey,
    ) -> Instruction {
        Instruction::new_with_bytes(
            self.program_id,
            &spt_x402_escrow::instruction::InitEscrow { amount: AMOUNT, resource_id, nonce, issuer }.data(),
            spt_x402_escrow::accounts::InitEscrow {
                payer: self.payer.pubkey(),
                config: self.config,
                recipient: self.recipient,
                mint: self.mint,
                escrow,
                vault,
                payer_ata: self.payer_ata,
                token_program: SPL_TOKEN_ID,
                system_program: system_program::ID,
                rent: RENT_SYSVAR_ID,
            }
            .to_account_metas(None),
        )
    }

    fn release_ix(&self, escrow: Pubkey, vault: Pubkey, spent: Pubkey) -> Instruction {
        Instruction::new_with_bytes(
            self.program_id,
            &spt_x402_escrow::instruction::ReleaseWithProof {}.data(),
            spt_x402_escrow::accounts::ReleaseWithProof {
                config: self.config,
                escrow,
                vault,
                recipient_ata: self.recipient_ata,
                payer_refund: self.payer.pubkey(),
                instructions: INSTRUCTIONS_SYSVAR_ID,
                releaser: self.releaser.pubkey(),
                spent_marker: spent,
                token_program: SPL_TOKEN_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    }

    /// Derive the binding and the escrow/vault/spent PDAs for one payment.
    fn derive(&self, resource_id: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], Pubkey, Pubkey, Pubkey) {
        let binding =
            compute_binding(&self.payer.pubkey(), &self.mint, AMOUNT, &self.recipient, resource_id, nonce);
        let (escrow, _) = Pubkey::find_program_address(
            &[SEED_ESCROW, self.payer.pubkey().as_ref(), self.recipient.as_ref(), &binding],
            &self.program_id,
        );
        let (vault, _) = Pubkey::find_program_address(&[SEED_VAULT, escrow.as_ref()], &self.program_id);
        let (spent, _) = Pubkey::find_program_address(&[SEED_SPENT, &binding], &self.program_id);
        (binding, escrow, vault, spent)
    }

    /// A real Ed25519 attestation over `binding`, signed by `signer`, fresh now.
    fn attestation_ix(&self, binding: &[u8; 32], signer: &Keypair) -> Instruction {
        let clock: anchor_lang::prelude::Clock = self.svm.get_sysvar();
        let token_msg = build_token_msg(binding, clock.unix_timestamp);
        let pk: [u8; 32] = signer.pubkey().to_bytes();
        let sig: [u8; 64] = <[u8; 64]>::try_from(signer.sign_message(&token_msg).as_ref()).unwrap();
        build_ed25519_ix(&pk, &sig, &token_msg)
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

#[test]
fn happy_path_then_replay_blocked() {
    let mut fx = bootstrapped();

    let resource_id = [0x44u8; 32];
    let nonce = [0x55u8; 32];
    let (binding, escrow, vault, spent) = fx.derive(&resource_id, &nonce);

    // init_escrow — deposits AMOUNT into the program-owned vault, pinned to issuer.
    let init_ix = fx.init_escrow_ix(fx.issuer.pubkey(), resource_id, nonce, escrow, vault);
    assert!(send(&mut fx.svm, &[init_ix.clone()], &fx.payer, &[&fx.payer]), "init_escrow failed");

    let ed_ix = fx.attestation_ix(&binding, &fx.issuer);
    let rel_ix = fx.release_ix(escrow, vault, spent);

    // release_with_proof — the Ed25519 ix must precede the release ix.
    assert!(
        send(&mut fx.svm, &[ed_ix.clone(), rel_ix.clone()], &fx.releaser, &[&fx.releaser]),
        "release_with_proof failed"
    );
    assert_eq!(token_amount(&fx.svm, &fx.recipient_ata), AMOUNT, "recipient was not paid");
    assert!(fx.svm.get_account(&escrow).map_or(true, |a| a.data.is_empty()), "escrow not closed");
    assert!(fx.svm.get_account(&spent).is_some(), "spent-marker not created");

    // REPLAY: re-fund and re-create the same escrow (same nonce), then replay the
    // identical attestation. Must FAIL at the spent-marker init.
    let (mint, payer_ata, payer_pk) = (fx.mint, fx.payer_ata, fx.payer.pubkey());
    inject(&mut fx.svm, &payer_ata, &SPL_TOKEN_ID, spl_token_account_data(&mint, &payer_pk, AMOUNT));
    assert!(send(&mut fx.svm, &[init_ix], &fx.payer, &[&fx.payer]), "escrow re-init failed");
    assert!(
        !send(&mut fx.svm, &[ed_ix, rel_ix], &fx.releaser, &[&fx.releaser]),
        "REPLAY WAS ACCEPTED — spent-marker did not block a captured attestation (Finding 1 regressed)"
    );
}

/// THREAT-MODEL T9, the property this hardening exists for: a FULLY COMPROMISED
/// ADMIN cannot cause an unauthorized release. The attacker holds the admin key,
/// adds an issuer they control, and signs a valid, fresh, correctly-bound
/// attestation. It is still refused, because the escrow pinned a different issuer
/// at deposit and the pin is immutable.
#[test]
fn compromised_admin_cannot_release_a_pinned_escrow() {
    let mut fx = bootstrapped();

    let resource_id = [0x11u8; 32];
    let nonce = [0x22u8; 32];
    let (binding, escrow, vault, spent) = fx.derive(&resource_id, &nonce);

    // Payer deposits, pinning the honest issuer.
    let init_ix = fx.init_escrow_ix(fx.issuer.pubkey(), resource_id, nonce, escrow, vault);
    assert!(send(&mut fx.svm, &[init_ix], &fx.payer, &[&fx.payer]), "init_escrow failed");

    // ── the admin key is now in the attacker's hands ──
    let rogue = Keypair::new();
    let ix = fx.add_issuer_ix(fx.admin.pubkey(), rogue.pubkey());
    assert!(send(&mut fx.svm, &[ix], &fx.admin, &[&fx.admin]), "add_issuer(rogue) failed");

    // The rogue issuer IS allowlisted, and its attestation IS cryptographically
    // valid and correctly bound to this exact escrow. Only the pin stands in the way.
    let ed_ix = fx.attestation_ix(&binding, &rogue);
    let rel_ix = fx.release_ix(escrow, vault, spent);
    assert!(
        send_expecting(
            &mut fx.svm,
            &[ed_ix, rel_ix],
            &fx.releaser,
            &[&fx.releaser],
            EscrowError::IssuerNotPinned,
        ),
        "COMPROMISED ADMIN RELEASED FUNDS — issuer pinning regressed (T9)"
    );
    assert_eq!(token_amount(&fx.svm, &fx.recipient_ata), 0, "recipient was paid by a rogue issuer");
    assert!(fx.svm.get_account(&spent).map_or(true, |a| a.data.is_empty()), "spent-marker was created");
}

/// Revocation must still bite escrows already in flight: pinning is ANDed with the
/// allowlist, it does not replace it. A second issuer stays on the list so this
/// exercises the per-issuer check rather than the empty-allowlist guard.
#[test]
fn revoked_issuer_cannot_release_even_when_pinned() {
    let mut fx = bootstrapped();

    let decoy = Keypair::new().pubkey();
    let ix = fx.add_issuer_ix(fx.admin.pubkey(), decoy);
    assert!(send(&mut fx.svm, &[ix], &fx.admin, &[&fx.admin]), "add_issuer(decoy) failed");

    let resource_id = [0x33u8; 32];
    let nonce = [0x66u8; 32];
    let (binding, escrow, vault, spent) = fx.derive(&resource_id, &nonce);

    let init_ix = fx.init_escrow_ix(fx.issuer.pubkey(), resource_id, nonce, escrow, vault);
    assert!(send(&mut fx.svm, &[init_ix], &fx.payer, &[&fx.payer]), "init_escrow failed");

    // Issuer compromise detected → the admin revokes it mid-flight.
    let ix = fx.remove_issuer_ix(fx.admin.pubkey(), fx.issuer.pubkey());
    assert!(send(&mut fx.svm, &[ix], &fx.admin, &[&fx.admin]), "remove_issuer failed");

    let ed_ix = fx.attestation_ix(&binding, &fx.issuer);
    let rel_ix = fx.release_ix(escrow, vault, spent);
    assert!(
        send_expecting(
            &mut fx.svm,
            &[ed_ix, rel_ix],
            &fx.releaser,
            &[&fx.releaser],
            EscrowError::IssuerNotAuthorized,
        ),
        "REVOKED ISSUER RELEASED FUNDS — pinning must AND with the allowlist, not replace it"
    );
    assert_eq!(token_amount(&fx.svm, &fx.recipient_ata), 0, "recipient was paid by a revoked issuer");
}

/// A payer cannot pin an issuer nobody authorized: the deposit is refused up front
/// rather than becoming an unreleasable escrow that has to wait out expiry.
#[test]
fn cannot_pin_an_unauthorized_issuer() {
    let mut fx = bootstrapped();

    let resource_id = [0x77u8; 32];
    let nonce = [0x88u8; 32];
    let (_binding, escrow, vault, _spent) = fx.derive(&resource_id, &nonce);

    let stranger = Keypair::new().pubkey();
    let init_ix = fx.init_escrow_ix(stranger, resource_id, nonce, escrow, vault);
    assert!(
        send_expecting(&mut fx.svm, &[init_ix], &fx.payer, &[&fx.payer], EscrowError::IssuerNotAuthorized),
        "escrow accepted a pin for an unauthorized issuer"
    );
}

/// Separation of duties is a runtime constraint, not a deploy convention:
/// init_config refuses to record the upgrade authority as the admin.
#[test]
fn init_config_refuses_to_collapse_the_two_roles() {
    let mut fx = base();
    let ua_pk = fx.upgrade_authority.pubkey();
    let ix = fx.init_config_ix(ua_pk);
    assert!(
        send_expecting(
            &mut fx.svm,
            &[ix],
            &fx.upgrade_authority,
            &[&fx.upgrade_authority],
            EscrowError::AdminIsUpgradeAuthority,
        ),
        "init_config allowed one key to hold both the upgrade authority and the admin role"
    );
}

/// The front-run defence: someone who is not the upgrade authority cannot get in
/// first and name themselves admin.
#[test]
fn init_config_rejects_a_non_upgrade_authority_signer() {
    let mut fx = base();
    let attacker = Keypair::new();
    fx.svm.airdrop(&attacker.pubkey(), 1_000_000_000).unwrap();

    let ix = Instruction::new_with_bytes(
        fx.program_id,
        &spt_x402_escrow::instruction::InitConfig {}.data(),
        spt_x402_escrow::accounts::InitConfig {
            config: fx.config,
            upgrade_authority: attacker.pubkey(),
            admin: Keypair::new().pubkey(),
            program: fx.program_id,
            program_data: fx.program_data,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    );
    assert!(
        send_expecting(&mut fx.svm, &[ix], &attacker, &[&attacker], EscrowError::NotUpgradeAuthority),
        "init_config was front-runnable by a non-upgrade-authority signer"
    );
}

/// Two-step admin rotation: propose, then accept. A nominee that never accepts
/// changes nothing, and the outgoing admin keeps working until handover completes.
#[test]
fn admin_rotation_is_two_step_and_transfers_the_role() {
    let mut fx = bootstrapped();
    let new_admin = Keypair::new();
    fx.svm.airdrop(&new_admin.pubkey(), 1_000_000_000).unwrap();

    let ix = fx.propose_admin_ix(fx.admin.pubkey(), new_admin.pubkey());
    assert!(send(&mut fx.svm, &[ix], &fx.admin, &[&fx.admin]), "propose_admin failed");

    // The old admin still holds the role until the nominee accepts.
    let ix = fx.add_issuer_ix(fx.admin.pubkey(), Keypair::new().pubkey());
    assert!(send(&mut fx.svm, &[ix], &fx.admin, &[&fx.admin]), "old admin lost the role before handover");

    // A third party cannot accept in the nominee's place.
    let interloper = Keypair::new();
    fx.svm.airdrop(&interloper.pubkey(), 1_000_000_000).unwrap();
    let ix = fx.accept_admin_ix(interloper.pubkey());
    assert!(
        send_expecting(&mut fx.svm, &[ix], &interloper, &[&interloper], EscrowError::NoPendingAdmin),
        "a non-nominee accepted the admin role"
    );

    // The nominee accepts — the role transfers.
    let ix = fx.accept_admin_ix(new_admin.pubkey());
    assert!(send(&mut fx.svm, &[ix], &new_admin, &[&new_admin]), "accept_admin failed");

    let ix = fx.add_issuer_ix(new_admin.pubkey(), Keypair::new().pubkey());
    assert!(send(&mut fx.svm, &[ix], &new_admin, &[&new_admin]), "new admin cannot add an issuer");

    let ix = fx.add_issuer_ix(fx.admin.pubkey(), Keypair::new().pubkey());
    assert!(
        !send(&mut fx.svm, &[ix], &fx.admin, &[&fx.admin]),
        "OLD ADMIN STILL HOLDS THE ROLE after handover"
    );
}

/// Rotation cannot quietly re-collapse the roles: handing the admin seat to the
/// upgrade authority is refused at accept time, not only at init.
#[test]
fn admin_rotation_refuses_the_upgrade_authority() {
    let mut fx = bootstrapped();
    let ua_pk = fx.upgrade_authority.pubkey();

    let ix = fx.propose_admin_ix(fx.admin.pubkey(), ua_pk);
    assert!(send(&mut fx.svm, &[ix], &fx.admin, &[&fx.admin]), "propose_admin failed");

    let ix = fx.accept_admin_ix(ua_pk);
    assert!(
        send_expecting(
            &mut fx.svm,
            &[ix],
            &fx.upgrade_authority,
            &[&fx.upgrade_authority],
            EscrowError::AdminIsUpgradeAuthority,
        ),
        "rotation collapsed the upgrade authority and admin into one key"
    );
}
