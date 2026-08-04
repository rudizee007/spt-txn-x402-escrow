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
    ///
    /// The admin is NOT the signer. The upgrade authority signs — which is what
    /// blocks the front-run — and *names* a different key as issuer admin. The
    /// account constraints refuse to let one key hold both roles.
    pub fn init_config(ctx: Context<InitConfig>) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.pending_admin = Pubkey::default();
        cfg.issuers = Vec::new();
        cfg.bump = ctx.bumps.config;
        emit!(AdminChanged { previous: Pubkey::default(), current: cfg.admin });
        Ok(())
    }

    /// Admin-only step 1 of 2: nominate a successor admin. Nothing changes yet —
    /// the nominee must call `accept_admin`, which proves the key is real and held.
    pub fn propose_admin(ctx: Context<AdminConfig>, new_admin: Pubkey) -> Result<()> {
        require!(new_admin != Pubkey::default(), EscrowError::InvalidAdmin);
        let cfg = &mut ctx.accounts.config;
        cfg.pending_admin = new_admin;
        emit!(AdminProposed { current: cfg.admin, nominee: new_admin });
        Ok(())
    }

    /// Step 2 of 2: the nominee claims the role. The upgrade-authority separation
    /// is re-checked here, so rotation cannot quietly collapse the two roles back
    /// into one key months after deployment.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(cfg.pending_admin != Pubkey::default(), EscrowError::NoPendingAdmin);
        let previous = cfg.admin;
        cfg.admin = cfg.pending_admin;
        cfg.pending_admin = Pubkey::default();
        emit!(AdminChanged { previous, current: cfg.admin });
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
        issuer: Pubkey,
    ) -> Result<()> {
        require!(amount > 0, EscrowError::InvalidAmount);

        // Fail fast: refuse to escrow against an issuer nobody has authorized. The
        // pin is what protects this escrow later; a garbage pin would make the
        // deposit unreleasable and force the payer to sit out the expiry window.
        require!(
            ctx.accounts.config.is_authorized(&issuer),
            EscrowError::IssuerNotAuthorized
        );

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
        escrow.issuer = issuer;
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

        // 3. Issuer must be allowlisted (deny-by-default). Revocation is immediate
        //    and applies to escrows already in flight.
        require!(cfg.is_authorized(&att.issuer), EscrowError::IssuerNotAuthorized);

        // 3b. AND it must be the issuer this payer pinned at deposit. A compromised
        //     admin can add a rogue issuer, but cannot reach any escrow that already
        //     exists, because the pin is immutable and predates the compromise. The
        //     two checks are ANDed, never substituted for one another (T9).
        require!(
            verify::ct_eq_32(&att.issuer.to_bytes(), &ctx.accounts.escrow.issuer.to_bytes()),
            EscrowError::IssuerNotPinned
        );

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
        init, payer = upgrade_authority, space = Config::MAX_SIZE,
        seeds = [SEED_CONFIG], bump
    )]
    pub config: Account<'info, Config>,

    /// The deployer. Must be the program's upgrade authority — that requirement is
    /// what blocks the init_config front-run. It does NOT become the admin.
    #[account(mut)]
    pub upgrade_authority: Signer<'info>,

    /// The issuer-allowlist admin: recorded, not required to sign, and refused if
    /// it is the upgrade authority. Separation of duties is enforced here rather
    /// than asserted in deploy notes.
    /// CHECK: stored as `Config.admin`; holds no authority over any vault or escrow.
    #[account(
        constraint = admin.key() != Pubkey::default() @ EscrowError::InvalidAdmin,
        constraint = admin.key() != upgrade_authority.key() @ EscrowError::AdminIsUpgradeAuthority
    )]
    pub admin: UncheckedAccount<'info>,

    /// This program — ties `program_data` to us via its stored programdata address,
    /// so a foreign ProgramData can't be substituted (Finding 3).
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ EscrowError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::SptX402Escrow>,
    /// The program's ProgramData — the SIGNER must be the upgrade authority. This
    /// blocks the init_config front-run: only the deployer can name the admin.
    #[account(constraint = program_data.upgrade_authority_address == Some(upgrade_authority.key()) @ EscrowError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// The nominee from `propose_admin`, proving control by signing.
    #[account(constraint = new_admin.key() == config.pending_admin @ EscrowError::NoPendingAdmin)]
    pub new_admin: Signer<'info>,

    /// CHECK: see InitConfig — binds `program_data` to this program.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ EscrowError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::SptX402Escrow>,
    /// Re-asserts separation of duties at rotation time: the incoming admin must
    /// not be the current upgrade authority. Checking only at `init_config` would
    /// let the invariant lapse the first time the role is handed over.
    #[account(constraint = program_data.upgrade_authority_address != Some(new_admin.key()) @ EscrowError::AdminIsUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
}

#[derive(Accounts)]
pub struct AdminConfig<'info> {
    #[account(mut, seeds = [SEED_CONFIG], bump = config.bump, has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(amount: u64, resource_id: [u8; 32], nonce: [u8; 32], issuer: Pubkey)]
pub struct InitEscrow<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Read-only: used to reject a pin that is not currently an authorized issuer.
    #[account(seeds = [SEED_CONFIG], bump = config.bump)]
    pub config: Account<'info, Config>,

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
pub struct AdminProposed { pub current: Pubkey, pub nominee: Pubkey }
#[event]
pub struct AdminChanged { pub previous: Pubkey, pub current: Pubkey }
#[event]
pub struct IssuerAdded { pub issuer: Pubkey }
#[event]
pub struct IssuerRemoved { pub issuer: Pubkey }
#[event]
pub struct Released { pub payer: Pubkey, pub recipient: Pubkey, pub amount: u64, pub issuer: Pubkey }
#[event]
pub struct Refunded { pub payer: Pubkey, pub amount: u64 }
