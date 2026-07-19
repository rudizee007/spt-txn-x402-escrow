//! spt_x402_escrow — on-chain enforcement of SPT-Txn authorization for x402
//! payments on Solana. See docs/SPEC.md and docs/THREAT-MODEL.md.
//!
//! Trust-boundary code: not for mainnet before adversarial review, property/fuzz
//! tests, and human line-by-line review.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, CloseAccount, Mint, Token, TokenAccount, Transfer};

pub mod constants;
pub mod errors;
pub mod state;
pub mod verify;

use constants::*;
use errors::EscrowError;
use state::{Config, Escrow, SpentMarker};

// Placeholder (valid base58) — replaced by `anchor keys sync` with the real id.
declare_id!("C9kTmtYm5V8cFfNvgzJAcVfM2zYN1Pqv245Xe27h4NwZ");

#[program]
pub mod spt_x402_escrow {
    use super::*;

    /// One-time setup: create the Config with an admin and an EMPTY issuer
    /// allowlist (deny-by-default; nobody is authorized until explicitly added).
    pub fn init_config(ctx: Context<InitConfig>) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.issuers = Vec::new();
        cfg.bump = ctx.bumps.config;
        Ok(())
    }

    /// Admin-only: authorize an SPT-Txn issuer Ed25519 public key.
    pub fn add_issuer(ctx: Context<AdminConfig>, issuer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(cfg.issuers.len() < MAX_ISSUERS, EscrowError::AllowlistFull);
        require!(!cfg.is_authorized(&issuer), EscrowError::IssuerAlreadyPresent);
        cfg.issuers.push(issuer);
        emit!(IssuerAdded { issuer });
        Ok(())
    }

    /// Admin-only: revoke an issuer.
    pub fn remove_issuer(ctx: Context<AdminConfig>, issuer: Pubkey) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        let before = cfg.issuers.len();
        cfg.issuers.retain(|k| k != &issuer);
        if cfg.issuers.len() != before {
            emit!(IssuerRemoved { issuer });
        }
        Ok(())
    }

    /// Deposit an x402 payment into escrow. Authorization is NOT asserted here —
    /// this is custody setup only (SPEC §5.1). `binding` is computed on-chain from
    /// the real escrow parameters so the stored value is trustworthy.
    pub fn init_escrow(
        ctx: Context<InitEscrow>,
        amount: u64,
        resource_id: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<()> {
        require!(amount > 0, EscrowError::InvalidAmount);

        // Binding is instance-unique (payer + nonce), so the issuer attestation
        // that later releases this escrow cannot release any other (THREAT-MODEL T4).
        let binding = verify::compute_binding(
            &ctx.accounts.payer.key(),
            &ctx.accounts.mint.key(),
            amount,
            &ctx.accounts.recipient.key(),
            &resource_id,
            &nonce,
        );

        let now = Clock::get()?.unix_timestamp;
        let expiry_ts = now.checked_add(MAX_ESCROW_SECS).ok_or(EscrowError::MathOverflow)?;

        let escrow = &mut ctx.accounts.escrow;
        escrow.payer = ctx.accounts.payer.key();
        escrow.recipient = ctx.accounts.recipient.key();
        escrow.mint = ctx.accounts.mint.key();
        escrow.amount = amount;
        escrow.binding = binding;
        escrow.nonce = nonce;
        escrow.expiry_ts = expiry_ts;
        escrow.bump = ctx.bumps.escrow;
        escrow.vault_bump = ctx.bumps.vault;

        // Move funds payer -> vault (owned by the escrow PDA).
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                Transfer {
                    from: ctx.accounts.payer_ata.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                },
            ),
            amount,
        )?;
        Ok(())
    }

    /// Release the escrow to the recipient IFF a valid, authorized, fresh,
    /// correctly-bound issuer attestation is present (SPEC §5.2). Fails closed.
    pub fn release_with_proof(ctx: Context<ReleaseWithProof>) -> Result<()> {
        let cfg = &ctx.accounts.config;
        require!(!cfg.issuers.is_empty(), EscrowError::AllowlistUninitialized);

        // 1–2. Introspect the native Ed25519 precompile result: pubkey + message.
        let att = verify::find_and_verify_attestation(&ctx.accounts.instructions.to_account_info())?;

        // 3. Issuer must be allowlisted (deny-by-default).
        require!(cfg.is_authorized(&att.issuer), EscrowError::IssuerNotAuthorized);

        // 4. Constant-time binding equality: does the signed payment == this escrow?
        require!(
            verify::ct_eq_32(&att.binding, &ctx.accounts.escrow.binding),
            EscrowError::BindingMismatch
        );

        // 5. Freshness + escrow not expired.
        let now = Clock::get()?.unix_timestamp;
        verify::check_freshness(att.iat, now)?;
        require!(now <= ctx.accounts.escrow.expiry_ts, EscrowError::EscrowExpired);

        // ── All checks passed: pay the recipient, then close vault + escrow ──
        let payer = ctx.accounts.escrow.payer;
        let recipient = ctx.accounts.escrow.recipient;
        let binding = ctx.accounts.escrow.binding;
        let bump = ctx.accounts.escrow.bump;
        let seeds: &[&[u8]] = &[SEED_ESCROW, payer.as_ref(), recipient.as_ref(), &binding, &[bump]];
        let signer = &[seeds];

        // Transfer the vault's LIVE balance, not the stored amount, so a dust
        // deposit into the vault cannot block close_account and trap funds
        // (adversarial-review Finding 2). Extra dust harmlessly follows the funds.
        let amount = ctx.accounts.vault.amount;
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.recipient_ata.to_account_info(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                signer,
            ),
            amount,
        )?;

        // Close the (now-empty) vault, rent to payer.
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.payer_refund.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            signer,
        ))?;

        emit!(Released { payer, recipient, amount, issuer: att.issuer });
        // Escrow account closed via `close = payer_refund` constraint (single-use).
        Ok(())
    }

    /// After expiry, return the escrowed funds to the payer. Callable by anyone;
    /// only the destination (the stored payer) is fixed (SPEC §5.3, THREAT-MODEL T6).
    pub fn refund_expired(ctx: Context<RefundExpired>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        require!(now > ctx.accounts.escrow.expiry_ts, EscrowError::RefundBeforeExpiry);

        let payer = ctx.accounts.escrow.payer;
        let recipient = ctx.accounts.escrow.recipient;
        let binding = ctx.accounts.escrow.binding;
        let bump = ctx.accounts.escrow.bump;
        let seeds: &[&[u8]] = &[SEED_ESCROW, payer.as_ref(), recipient.as_ref(), &binding, &[bump]];
        let signer = &[seeds];

        // Transfer the vault's LIVE balance, not the stored amount, so a dust
        // deposit into the vault cannot block close_account and trap funds
        // (adversarial-review Finding 2). Extra dust harmlessly follows the funds.
        let amount = ctx.accounts.vault.amount;
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.payer_ata.to_account_info(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                signer,
            ),
            amount,
        )?;
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.payer_ata_owner.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            signer,
        ))?;
        emit!(Refunded { payer, amount });
        Ok(())
    }
}

// ─────────────────────────── Account contexts ──────────────────────────────

#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(
        init, payer = admin, space = Config::MAX_SIZE,
        seeds = [SEED_CONFIG], bump
    )]
    pub config: Account<'info, Config>,
    #[account(mut)]
    pub admin: Signer<'info>,
    /// This program — ties `program_data` to us via its stored programdata address,
    /// so a foreign ProgramData can't be substituted (Finding 3).
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ EscrowError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::SptX402Escrow>,
    /// The program's ProgramData — `admin` MUST be the upgrade authority. This
    /// blocks the init_config front-run: only the deployer can set the admin.
    #[account(constraint = program_data.upgrade_authority_address == Some(admin.key()) @ EscrowError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminConfig<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(amount: u64, resource_id: [u8; 32], nonce: [u8; 32])]
pub struct InitEscrow<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: recipient is bound into the escrow + binding; not required to sign.
    pub recipient: UncheckedAccount<'info>,
    pub mint: Account<'info, Mint>,

    #[account(
        init, payer = payer, space = Escrow::MAX_SIZE,
        seeds = [
            SEED_ESCROW,
            payer.key().as_ref(),
            recipient.key().as_ref(),
            &verify::compute_binding(&payer.key(), &mint.key(), amount, &recipient.key(), &resource_id, &nonce)
        ],
        bump
    )]
    pub escrow: Account<'info, Escrow>,

    #[account(
        init, payer = payer,
        seeds = [SEED_VAULT, escrow.key().as_ref()], bump,
        token::mint = mint, token::authority = escrow
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut, constraint = payer_ata.mint == mint.key(), constraint = payer_ata.owner == payer.key())]
    pub payer_ata: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct ReleaseWithProof<'info> {
    #[account(seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [SEED_ESCROW, escrow.payer.as_ref(), escrow.recipient.as_ref(), &escrow.binding],
        bump = escrow.bump,
        close = payer_refund
    )]
    pub escrow: Account<'info, Escrow>,

    #[account(mut, seeds = [SEED_VAULT, escrow.key().as_ref()], bump = escrow.vault_bump)]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut, constraint = recipient_ata.owner == escrow.recipient, constraint = recipient_ata.mint == escrow.mint)]
    pub recipient_ata: Account<'info, TokenAccount>,

    /// CHECK: receives escrow-account rent on close and vault rent on close.
    #[account(mut, address = escrow.payer)]
    pub payer_refund: UncheckedAccount<'info>,

    /// CHECK: address-checked native Instructions sysvar; read-only introspection.
    #[account(address = INSTRUCTIONS_SYSVAR_ID)]
    pub instructions: UncheckedAccount<'info>,

    /// Pays the tx fee and the permanent spent-marker rent. Any party may submit a
    /// release; the releaser holds no privileged control over the funds — the
    /// attestation is the authorization, and all destinations are fixed.
    #[account(mut)]
    pub releaser: Signer<'info>,

    /// Permanent single-use marker at [SEED_SPENT, binding]. `init` here fails if
    /// this binding was already released, which structurally blocks replay of a
    /// captured attestation against a re-created escrow (Finding 1).
    #[account(
        init, payer = releaser, space = SpentMarker::MAX_SIZE,
        seeds = [SEED_SPENT, escrow.binding.as_ref()], bump
    )]
    pub spent_marker: Account<'info, SpentMarker>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RefundExpired<'info> {
    #[account(
        mut,
        seeds = [SEED_ESCROW, escrow.payer.as_ref(), escrow.recipient.as_ref(), &escrow.binding],
        bump = escrow.bump,
        close = payer_ata_owner
    )]
    pub escrow: Account<'info, Escrow>,

    #[account(mut, seeds = [SEED_VAULT, escrow.key().as_ref()], bump = escrow.vault_bump)]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut, constraint = payer_ata.owner == escrow.payer, constraint = payer_ata.mint == escrow.mint)]
    pub payer_ata: Account<'info, TokenAccount>,

    /// CHECK: the escrow's payer receives the escrow-account rent on close.
    #[account(mut, address = escrow.payer)]
    pub payer_ata_owner: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
}

// ───────────────────────────────── Events ──────────────────────────────────

#[event]
pub struct IssuerAdded { pub issuer: Pubkey }
#[event]
pub struct IssuerRemoved { pub issuer: Pubkey }
#[event]
pub struct Released { pub payer: Pubkey, pub recipient: Pubkey, pub amount: u64, pub issuer: Pubkey }
#[event]
pub struct Refunded { pub payer: Pubkey, pub amount: u64 }
