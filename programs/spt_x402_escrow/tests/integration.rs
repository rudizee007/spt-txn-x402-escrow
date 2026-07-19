//! litesvm end-to-end integration test. Proves at runtime what the unit tests
//! prove in logic: the full escrow lifecycle works, the Ed25519 sysvar
//! introspection finds and binds the attestation, and a replayed attestation is
//! rejected by the permanent spent-marker (adversarial-review Finding 1).
//!
//! Requires the built program: run `anchor build` first, then `cargo test`.
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
    spt_x402_escrow::{constants::*, verify::compute_binding},
};

const SPL_TOKEN_ID: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const RENT_SYSVAR_ID: Pubkey = Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
const BPF_LOADER_UPGRADEABLE_ID: Pubkey = Pubkey::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const AMOUNT: u64 = 1_000_000;

fn load_svm() -> (LiteSVM, Pubkey) {
    let program_id = spt_x402_escrow::id();
    let mut svm = LiteSVM::new();
    let bytes = include_bytes!(concat!(env!("CARGO_TARGET_TMPDIR"), "/../deploy/spt_x402_escrow.so"));
    svm.add_program(program_id, bytes).unwrap();
    (svm, program_id)
}

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

#[test]
fn happy_path_then_replay_blocked() {
    let (mut svm, program_id) = load_svm();

    let admin = Keypair::new();
    let payer = Keypair::new();
    let releaser = Keypair::new();
    let issuer = Keypair::new(); // the SPT-Txn attestation signer
    let recipient = Keypair::new().pubkey();
    let mint = Keypair::new().pubkey();
    let payer_ata = Keypair::new().pubkey();
    let recipient_ata = Keypair::new().pubkey();

    for kp in [&admin, &payer, &releaser] {
        svm.airdrop(&kp.pubkey(), 1_000_000_000).unwrap();
    }
    inject(&mut svm, &mint, &SPL_TOKEN_ID, spl_mint_data(&admin.pubkey(), AMOUNT, 0));
    inject(&mut svm, &payer_ata, &SPL_TOKEN_ID, spl_token_account_data(&mint, &payer.pubkey(), AMOUNT));
    inject(&mut svm, &recipient_ata, &SPL_TOKEN_ID, spl_token_account_data(&mint, &recipient, 0));

    let (config, _) = Pubkey::find_program_address(&[SEED_CONFIG], &program_id);

    // Finding 3: make `admin` the program's upgrade authority so init_config's gate
    // passes. litesvm loads the program with upgrade_authority = None, so patch the
    // ProgramData metadata: [0..4]=variant(3=ProgramData), [4..12]=slot,
    // [12]=Option tag(1=Some), [13..45]=authority pubkey.
    let (program_data, _) = Pubkey::find_program_address(&[program_id.as_ref()], &BPF_LOADER_UPGRADEABLE_ID);
    let mut pd = svm.get_account(&program_data).unwrap();
    pd.data[0..4].copy_from_slice(&3u32.to_le_bytes());
    pd.data[12] = 1;
    pd.data[13..45].copy_from_slice(admin.pubkey().as_ref());
    svm.set_account(program_data, pd).unwrap();

    // 1. init_config (gated to the upgrade authority)
    let ix = Instruction::new_with_bytes(
        program_id,
        &spt_x402_escrow::instruction::InitConfig {}.data(),
        spt_x402_escrow::accounts::InitConfig {
            config,
            admin: admin.pubkey(),
            program: program_id,
            program_data,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    );
    assert!(send(&mut svm, &[ix], &admin, &[&admin]), "init_config failed");

    // 2. add_issuer(issuer)
    let ix = Instruction::new_with_bytes(
        program_id,
        &spt_x402_escrow::instruction::AddIssuer { issuer: issuer.pubkey() }.data(),
        spt_x402_escrow::accounts::AdminConfig { config, admin: admin.pubkey() }.to_account_metas(None),
    );
    assert!(send(&mut svm, &[ix], &admin, &[&admin]), "add_issuer failed");

    // Escrow parameters + binding (instance-unique via payer + nonce).
    let resource_id = [0x44u8; 32];
    let nonce = [0x55u8; 32];
    let binding = compute_binding(&payer.pubkey(), &mint, AMOUNT, &recipient, &resource_id, &nonce);
    let (escrow, _) = Pubkey::find_program_address(
        &[SEED_ESCROW, payer.pubkey().as_ref(), recipient.as_ref(), &binding],
        &program_id,
    );
    let (vault, _) = Pubkey::find_program_address(&[SEED_VAULT, escrow.as_ref()], &program_id);
    let (spent, _) = Pubkey::find_program_address(&[SEED_SPENT, &binding], &program_id);

    // 3. init_escrow — deposits AMOUNT into the program-owned vault.
    let init_escrow_ix = || {
        Instruction::new_with_bytes(
            program_id,
            &spt_x402_escrow::instruction::InitEscrow { amount: AMOUNT, resource_id, nonce }.data(),
            spt_x402_escrow::accounts::InitEscrow {
                payer: payer.pubkey(),
                recipient,
                mint,
                escrow,
                vault,
                payer_ata,
                token_program: SPL_TOKEN_ID,
                system_program: system_program::ID,
                rent: RENT_SYSVAR_ID,
            }
            .to_account_metas(None),
        )
    };
    assert!(send(&mut svm, &[init_escrow_ix()], &payer, &[&payer]), "init_escrow failed");

    // Build the issuer attestation over the fixed token_msg. iat must track the
    // VM clock so the freshness check (±MAX_TOKEN_AGE_SECS) passes at runtime.
    let clock: anchor_lang::prelude::Clock = svm.get_sysvar();
    let iat = clock.unix_timestamp;
    let token_msg = build_token_msg(&binding, iat);
    let issuer_pk: [u8; 32] = issuer.pubkey().to_bytes();
    let sig: [u8; 64] = <[u8; 64]>::try_from(issuer.sign_message(&token_msg).as_ref()).unwrap();
    let ed_ix = build_ed25519_ix(&issuer_pk, &sig, &token_msg);

    let release_ix = || {
        Instruction::new_with_bytes(
            program_id,
            &spt_x402_escrow::instruction::ReleaseWithProof {}.data(),
            spt_x402_escrow::accounts::ReleaseWithProof {
                config,
                escrow,
                vault,
                recipient_ata,
                payer_refund: payer.pubkey(),
                instructions: INSTRUCTIONS_SYSVAR_ID,
                releaser: releaser.pubkey(),
                spent_marker: spent,
                token_program: SPL_TOKEN_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        )
    };

    // 4. release_with_proof — Ed25519 ix must precede the release ix.
    assert!(
        send(&mut svm, &[ed_ix.clone(), release_ix()], &releaser, &[&releaser]),
        "release_with_proof failed"
    );
    assert_eq!(token_amount(&svm, &recipient_ata), AMOUNT, "recipient was not paid");
    assert!(svm.get_account(&escrow).map_or(true, |a| a.data.is_empty()), "escrow not closed");
    assert!(svm.get_account(&spent).is_some(), "spent-marker not created");

    // 5. REPLAY: re-fund and re-create the same escrow (same nonce), then replay
    //    the identical attestation. Must FAIL at the spent-marker init.
    inject(&mut svm, &payer_ata, &SPL_TOKEN_ID, spl_token_account_data(&mint, &payer.pubkey(), AMOUNT));
    assert!(send(&mut svm, &[init_escrow_ix()], &payer, &[&payer]), "escrow re-init failed");
    assert!(
        !send(&mut svm, &[ed_ix, release_ix()], &releaser, &[&releaser]),
        "REPLAY WAS ACCEPTED — spent-marker did not block a captured attestation (Finding 1 regressed)"
    );
}
