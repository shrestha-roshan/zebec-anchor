//! The program is used from https://github.com/coral-xyz/multisig which provides
//! Grant of Copyright License
//! We want to thank all the contributors of coral-xyz/multisig
//! This program can be used to allow a multisig to govern anything a regular
//! Pubkey can govern. One can use the multisig as a BPF program upgrade
//! authority, a mint authority, etc.
//!
//! To use, one must first create a `Multisig` account, specifying two important
//! parameters:
//!
//! 1. Owners - the set of addresses that sign transactions for the multisig.
//! 2. Threshold - the number of signers required to execute a transaction.
//!
//! Once the `Multisig` account is created, one can create a `Transaction`
//! account, specifying the parameters for a normal solana transaction.
//!
//! To sign, owners should invoke the `approve` instruction, and finally,
//! the `execute_transaction`, once enough (i.e. `threshold`) of the owners have
//! signed.
//!

use anchor_lang::prelude::*;
use anchor_lang::solana_program;
use anchor_lang::solana_program::instruction::Instruction;
use std::convert::Into;
use std::ops::Deref;

declare_id!("b6ZPysThkApNx2YDiGsPUiYPE7Ub1kTRdCWp7gBkzbr");

#[program]
pub mod serum_multisig {
    use std::collections::HashSet;

    use anchor_lang::solana_program::program::invoke_signed;

    use super::*;

    // Initializes a new multisig account with a set of owners and a threshold.
    pub fn create_multisig(
        ctx: Context<CreateMultisig>,
        owners: Vec<Pubkey>,
        threshold: u64,
        nonce: u8,
    ) -> Result<()> {
        assert_unique_owners(&owners)?;
        require!(
            threshold > 0 && threshold <= owners.len() as u64,
            InvalidThreshold
        );
        require!(!owners.is_empty(), InvalidOwnersLen);

        let multisig = &mut ctx.accounts.multisig;
        multisig.owners = owners; //vector of publickey
        multisig.threshold = threshold; //8
        multisig.nonce = nonce; //1
        multisig.owner_set_seqno = 0; //4
        Ok(())
    }
    // Creates a new transaction account, automatically signed by the creator,
    // which must be one of the owners of the multisig.
    pub fn create_transaction(
        ctx: Context<CreateTransaction>,
        pid: Pubkey,
        accs: Vec<TransactionAccount>,
        data: Vec<u8>,
    ) -> Result<()> {
        let owner_index = ctx
            .accounts
            .multisig
            .owners
            .iter()
            .position(|a| a == ctx.accounts.proposer.key)
            .ok_or(ErrorCode::InvalidOwner)?;

        let mut signers = Vec::new();
        signers.resize(ctx.accounts.multisig.owners.len(), false);
        signers[owner_index] = true;

        let tx = &mut ctx.accounts.transaction;
        tx.program_id = pid;
        tx.accounts = accs;
        tx.data = data;
        tx.signers = signers;
        tx.multisig = ctx.accounts.multisig.key();
        tx.did_execute = false;
        tx.owner_set_seqno = ctx.accounts.multisig.owner_set_seqno;
        Ok(())
    }
    // Approves a transaction on behalf of an owner of the multisig.
    pub fn approve(ctx: Context<Approve>) -> Result<()> {
        let owner_index = ctx
            .accounts
            .multisig
            .owners
            .iter()
            .position(|a| a == ctx.accounts.owner.key)
            .ok_or(ErrorCode::InvalidOwner)?;
        /*if ctx.accounts.transaction.signers[owner_index]==true
        {
            return Err(ErrorCode::AlreadyApproved.into());
        }*/
        //as recommended by RGB sir
        ctx.accounts.transaction.signers[owner_index] = true;
        Ok(())
    }
    // Set owners and threshold at once.
    pub fn set_owners_and_change_threshold<'info>(
        ctx: Context<'_, '_, '_, 'info, Auth<'info>>,
        owners: Vec<Pubkey>,
        threshold: u64,
    ) -> Result<()> {
        set_owners(
            Context::new(
                ctx.program_id,
                ctx.accounts,
                ctx.remaining_accounts,
                ctx.bumps.clone(),
            ),
            owners,
        )?;
        change_threshold(ctx, threshold)
    }
    // Sets the owners field on the multisig. The only way this can be invoked
    // is via a recursive call from execute_transaction -> set_owners.
    pub fn set_owners(ctx: Context<Auth>, owners: Vec<Pubkey>) -> Result<()> {
        assert_unique_owners(&owners)?;
        require!(!owners.is_empty(), InvalidOwnersLen);

        let multisig = &mut ctx.accounts.multisig;

        if (owners.len() as u64) < multisig.threshold {
            multisig.threshold = owners.len() as u64;
        }

        multisig.owners = owners;
        multisig.owner_set_seqno += 1;

        Ok(())
    }
    // Changes the execution threshold of the multisig. The only way this can be
    // invoked is via a recursive call from execute_transaction ->
    // change_threshold.
    pub fn change_threshold(ctx: Context<Auth>, threshold: u64) -> Result<()> {
        require!(threshold > 0, InvalidThreshold);
        if threshold > ctx.accounts.multisig.owners.len() as u64 {
            return Err(ErrorCode::InvalidThreshold.into());
        }
        let multisig = &mut ctx.accounts.multisig;
        multisig.threshold = threshold;
        Ok(())
    }
    // Executes the given transaction if threshold owners have signed it.
    pub fn execute_transaction(ctx: Context<ExecuteTransaction>) -> Result<()> {
        // Has this been executed already?
        if ctx.accounts.transaction.did_execute {
            return Err(ErrorCode::AlreadyExecuted.into());
        }

        // Do we have enough signers.
        let sig_count = ctx
            .accounts
            .transaction
            .signers
            .iter()
            .filter(|&did_sign| *did_sign)
            .count() as u64;
        if sig_count < ctx.accounts.multisig.threshold {
            return Err(ErrorCode::NotEnoughSigners.into());
        }

        // Execute the transaction signed by the multisig.
        let mut ix: Instruction = (*ctx.accounts.transaction).deref().into();
        ix.accounts = ix
            .accounts
            .iter()
            .map(|acc| {
                let mut acc = acc.clone();
                if &acc.pubkey == ctx.accounts.multisig_signer.key {
                    acc.is_signer = true;
                }
                acc
            })
            .collect();
        let multisig_key = ctx.accounts.multisig.key();
        let seeds = &[multisig_key.as_ref(), &[ctx.accounts.multisig.nonce]];
        let signer = &[&seeds[..]];
        let accounts = ctx.remaining_accounts;
        solana_program::program::invoke_signed(&ix, accounts, signer)?;

        // Burn the transaction to ensure one time use.
        ctx.accounts.transaction.did_execute = true;

        Ok(())
    }

    pub fn create_request(ctx: Context<CreateRequest>, actions: Vec<RequestAction>) -> Result<()> {
        let multisig = &ctx.accounts.multisig;

        let owner_index = multisig
            .owners
            .iter()
            .position(|a| a == ctx.accounts.proposer.key)
            .ok_or(ErrorCode::InvalidOwner)?;

        let owners_len = multisig.owners.len();
        let owner_set_seqno = multisig.owner_set_seqno;

        let request = &mut ctx.accounts.request;
        request.apply_request(multisig.key(), actions, owner_set_seqno, owners_len);
        request.approve(owner_index);

        Ok(())
    }

    // Approves a request on behalf of an owner of the multisig.
    pub fn approve_request(ctx: Context<ApproveRequest>) -> Result<()> {
        let owner_index = ctx
            .accounts
            .multisig
            .owners
            .iter()
            .position(|a| a == ctx.accounts.owner.key)
            .ok_or(ErrorCode::InvalidOwner)?;
        ctx.accounts.request.approve(owner_index);
        Ok(())
    }

    pub fn execute_request(ctx: Context<ExecuteRequest>) -> Result<()> {
        if ctx.accounts.request.did_execute {
            return Err(ErrorCode::AlreadyExecuted.into());
        }

        // Do we have enough signers.
        let sig_count = ctx
            .accounts
            .request
            .signers
            .iter()
            .filter(|&did_sign| *did_sign)
            .count() as u64;

        if sig_count < ctx.accounts.multisig.threshold {
            return Err(ErrorCode::NotEnoughSigners.into());
        }

        let request = &ctx.accounts.request;
        let multisig_signer = ctx.accounts.multisig_signer.key;

        for action in request.clone().actions.iter() {
            let mut metas = action.get_account_metas();
            let mut unique_pubkeys: HashSet<Pubkey> = HashSet::new();

            for meta in &mut metas {
                unique_pubkeys.insert(meta.pubkey.clone());

                if meta.pubkey.eq(multisig_signer) {
                    meta.is_signer = true;
                }
            }

            let ix = Instruction {
                program_id: action.program_id,
                accounts: metas,
                data: action.data.clone(),
            };
            let multisig_key = ctx.accounts.multisig.key();
            let seeds = &[multisig_key.as_ref(), &[ctx.accounts.multisig.nonce]];
            let signer = &[&seeds[..]];
            let account_infos = unique_pubkeys
                .iter()
                .map(|pubkey| -> AccountInfo {
                    ctx.remaining_accounts
                        .iter()
                        .find(|&account| account.key().eq(pubkey))
                        .unwrap()
                        .clone()
                })
                .collect::<Vec<AccountInfo>>();
            invoke_signed(&ix, &account_infos, signer)?;
        }
        ctx.accounts.request.did_execute = true;
        Ok(())
    }
}
#[derive(Accounts)]
pub struct CreateMultisig<'info> {
    #[account(zero, signer)]
    multisig: Box<Account<'info, Multisig>>,
}
#[derive(Accounts)]
pub struct CreateTransaction<'info> {
    multisig: Box<Account<'info, Multisig>>,
    #[account(zero, signer)]
    transaction: Box<Account<'info, Transaction>>,
    // One of the owners. Checked in the handler.
    proposer: Signer<'info>,
}
#[derive(Accounts)]
pub struct Approve<'info> {
    #[account(constraint = multisig.owner_set_seqno == transaction.owner_set_seqno)]
    multisig: Box<Account<'info, Multisig>>,
    #[account(mut, has_one = multisig)]
    transaction: Box<Account<'info, Transaction>>,
    // One of the multisig owners. Checked in the handler.
    owner: Signer<'info>,
}
#[derive(Accounts)]
pub struct Auth<'info> {
    #[account(mut)]
    multisig: Box<Account<'info, Multisig>>,
    #[account(
        seeds = [multisig.key().as_ref()],
        bump = multisig.nonce,
    )]
    multisig_signer: Signer<'info>,
}
#[derive(Accounts)]
pub struct ExecuteTransaction<'info> {
    #[account(constraint = multisig.owner_set_seqno == transaction.owner_set_seqno)]
    multisig: Box<Account<'info, Multisig>>,
    /// CHECK: multisig_signer is a PDA program signer. Data is never read or written to
    #[account(
        seeds = [multisig.key().as_ref()],
        bump = multisig.nonce,
    )]
    multisig_signer: UncheckedAccount<'info>,
    #[account(mut, has_one = multisig)]
    transaction: Box<Account<'info, Transaction>>,
}

#[derive(Accounts)]
pub struct CreateRequest<'info> {
    pub multisig: Box<Account<'info, Multisig>>,
    #[account(mut, has_one = multisig)]
    pub request: Box<Account<'info, Request>>,
    pub proposer: Signer<'info>,
}
#[derive(Accounts)]
pub struct ApproveRequest<'info> {
    #[account(constraint = multisig.owner_set_seqno == request.owner_set_seqno)]
    multisig: Box<Account<'info, Multisig>>,
    #[account(mut, has_one = multisig)]
    request: Box<Account<'info, Request>>,
    // One of the multisig owners. Checked in the handler.
    owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExecuteRequest<'info> {
    #[account(constraint = multisig.owner_set_seqno == request.owner_set_seqno)]
    multisig: Box<Account<'info, Multisig>>,
    /// CHECK: multisig_signer is a PDA program signer. Data is never read or written to
    #[account(
        seeds = [multisig.key().as_ref()],
        bump = multisig.nonce,
    )]
    multisig_signer: UncheckedAccount<'info>,
    #[account(mut, has_one = multisig)]
    request: Box<Account<'info, Request>>,
}

#[account]
pub struct Request {
    pub multisig: Pubkey,
    pub actions: Vec<RequestAction>,
    pub signers: Vec<bool>,
    pub did_execute: bool,
    pub owner_set_seqno: u32,
}

impl Request {
    pub fn apply_request(
        &mut self,
        multisig: Pubkey,
        actions: Vec<RequestAction>,
        owner_set_seqno: u32,
        owner_len: usize,
    ) {
        self.multisig = multisig;
        self.actions = actions;
        self.did_execute = false;
        self.owner_set_seqno = owner_set_seqno;
        self.signers = Vec::new();
        self.signers.resize(owner_len, false);
    }

    pub fn approve(&mut self, index: usize) {
        self.signers[index] = true;
    }
}

#[derive(Clone, AnchorSerialize, AnchorDeserialize)]
pub struct RequestAction {
    pub program_id: Pubkey,
    pub accounts: Vec<TransactionAccount>,
    pub data: Vec<u8>,
}

impl RequestAction {
    pub fn get_account_metas(&self) -> Vec<AccountMeta> {
        self.accounts
            .iter()
            .map(|item| AccountMeta::from(item))
            .collect()
    }
}

#[account]
pub struct Multisig {
    pub owners: Vec<Pubkey>,
    pub threshold: u64,
    pub nonce: u8,
    pub owner_set_seqno: u32,
}

#[account]
pub struct Transaction {
    // The multisig account this transaction belongs to.
    pub multisig: Pubkey,
    // Target program to execute against.
    pub program_id: Pubkey,
    // Accounts requried for the transaction.
    pub accounts: Vec<TransactionAccount>,
    // Instruction data for the transaction.
    pub data: Vec<u8>,
    // signers[index] is true iff multisig.owners[index] signed the transaction.
    pub signers: Vec<bool>,
    // Boolean ensuring one time execution.
    pub did_execute: bool,
    // Owner set sequence number.
    pub owner_set_seqno: u32,
}

impl From<&Transaction> for Instruction {
    fn from(tx: &Transaction) -> Instruction {
        Instruction {
            program_id: tx.program_id,
            accounts: tx.accounts.iter().map(Into::into).collect(),
            data: tx.data.clone(),
        }
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TransactionAccount {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl From<&TransactionAccount> for AccountMeta {
    fn from(account: &TransactionAccount) -> AccountMeta {
        match account.is_writable {
            false => AccountMeta::new_readonly(account.pubkey, account.is_signer),
            true => AccountMeta::new(account.pubkey, account.is_signer),
        }
    }
}

impl From<&AccountMeta> for TransactionAccount {
    fn from(account_meta: &AccountMeta) -> TransactionAccount {
        TransactionAccount {
            pubkey: account_meta.pubkey,
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        }
    }
}

fn assert_unique_owners(owners: &[Pubkey]) -> Result<()> {
    for (i, owner) in owners.iter().enumerate() {
        require!(
            !owners.iter().skip(i + 1).any(|item| item == owner),
            UniqueOwners
        )
    }
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("The given owner is not part of this multisig.")]
    InvalidOwner,
    #[msg("Owners length must be non zero.")]
    InvalidOwnersLen,
    #[msg("Not enough owners signed this transaction.")]
    NotEnoughSigners,
    #[msg("Cannot delete a transaction that has been signed by an owner.")]
    TransactionAlreadySigned,
    #[msg("Overflow when adding.")]
    Overflow,
    #[msg("Cannot delete a transaction the owner did not create.")]
    UnableToDelete,
    #[msg("The given transaction has already been executed.")]
    AlreadyExecuted,
    #[msg("Threshold must be less than or equal to the number of owners.")]
    InvalidThreshold,
    #[msg("Owners must be unique")]
    UniqueOwners,
    #[msg("Already Approved")]
    AlreadyApproved,
}
