#![no_std]

use soroban_sdk::token::TokenClient;
use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Env, IntoVal, String, Symbol, Val, Vec,
};

pub mod access_control;
mod batch;
pub mod cooldown;
mod early_exit_penalty;
mod emergency;
mod events;
#[allow(dead_code)]
pub mod evidence;
mod fees;
pub mod governance_approval;
#[allow(dead_code)]
mod math;
mod nonce;
mod parameters;
pub mod pausable;
mod rolling_bond;
mod tiered_bond;
mod token_integration;
pub mod types;
mod validation;
pub mod verifier;
mod weighted_attestation;

use crate::access_control::{
    add_verifier_role, is_verifier, remove_verifier_role, require_verifier,
};

pub use batch::{BatchBondParams, BatchBondResult};
pub use evidence::{Evidence, EvidenceType};
pub use types::Attestation;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BondTier {
    Bronze,
    Silver,
    Gold,
    Platinum,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct IdentityBond {
    pub identity: Address,
    pub bonded_amount: i128,
    pub bond_start: u64,
    pub bond_duration: u64,
    pub slashed_amount: i128,
    pub active: bool,
    pub is_rolling: bool,
    pub withdrawal_requested_at: u64,
    pub notice_period_duration: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct CooldownRequest {
    pub requester: Address,
    pub amount: i128,
    pub requested_at: u64,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Bond,
    Attester(Address),
    Attestation(u64),
    AttestationCounter,
    SubjectAttestations(Address),
    DuplicateCheck(Address, Address, String),
    SubjectAttestationCount(Address),
    Nonce(Address),
    AttesterStake(Address),
    CooldownReq(Address),
    GovernanceNextProposalId,
    GovernanceProposal(u64),
    GovernanceVote(u64, Address),
    GovernanceDelegate(Address),
    GovernanceGovernors,
    GovernanceQuorumBps,
    GovernanceMinGovernors,
    FeeTreasury,
    FeeBps,
    EvidenceCounter,
    Evidence(u64),
    ProposalEvidence(u64),
    HashExists(String),
    Paused,
    PauseSigner(Address),
    PauseSignerCount,
    PauseThreshold,
    PauseProposalCounter,
    PauseProposal(u64),
    PauseApproval(u64, Address),
    PauseApprovalCount(u64),
    BondToken,
}

#[contract]
pub struct CredenceBond;

#[contractimpl]
impl CredenceBond {
    fn acquire_lock(e: &Env) {
        if Self::check_lock(e) {
            panic!("reentrancy detected");
        }
        e.storage().instance().set(&Self::lock_key(e), &true);
    }
    fn release_lock(e: &Env) {
        e.storage().instance().set(&Self::lock_key(e), &false);
    }
    fn check_lock(e: &Env) -> bool {
        e.storage()
            .instance()
            .get(&Self::lock_key(e))
            .unwrap_or(false)
    }
    fn lock_key(e: &Env) -> Symbol {
        Symbol::new(e, "lock")
    }
    fn callback_key(e: &Env) -> Symbol {
        Symbol::new(e, "callback")
    }
    #[allow(dead_code)]
    fn with_reentrancy_guard<T, F: FnOnce() -> T>(e: &Env, f: F) -> T {
        if Self::check_lock(e) {
            panic!("reentrancy detected");
        }
        Self::acquire_lock(e);
        let result = f();
        Self::release_lock(e);
        result
    }
    fn require_admin_internal(e: &Env, admin: &Address) {
        let stored: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("not initialized"));
        if stored != *admin {
            panic!("not admin");
        }
    }

    pub fn initialize(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
        e.storage().instance().set(&DataKey::Paused, &false);
        e.storage()
            .instance()
            .set(&DataKey::PauseSignerCount, &0_u32);
        e.storage().instance().set(&DataKey::PauseThreshold, &0_u32);
        e.storage()
            .instance()
            .set(&DataKey::PauseProposalCounter, &0_u64);
        e.storage()
            .instance()
            .set(&Symbol::new(&e, "admin"), &admin);
    }

    pub fn set_early_exit_config(e: Env, admin: Address, treasury: Address, penalty_bps: u32) {
        pausable::require_not_paused(&e);
        admin.require_auth();
        Self::require_admin_internal(&e, &admin);
        early_exit_penalty::set_config(&e, treasury, penalty_bps);
    }

    pub fn set_emergency_config(
        e: Env,
        admin: Address,
        governance: Address,
        treasury: Address,
        emergency_fee_bps: u32,
        enabled: bool,
    ) {
        admin.require_auth();
        Self::require_admin_internal(&e, &admin);
        emergency::set_config(&e, governance, treasury, emergency_fee_bps, enabled);
    }

    pub fn set_emergency_mode(e: Env, admin: Address, governance: Address, enabled: bool) {
        Self::require_admin_internal(&e, &admin);
        let cfg = emergency::get_config(&e);
        if governance != cfg.governance {
            panic!("not governance");
        }
        admin.require_auth();
        governance.require_auth();
        emergency::set_enabled(&e, enabled);
        emergency::emit_emergency_mode_event(&e, enabled, &admin, &governance);
    }

    pub fn emergency_withdraw(
        e: Env,
        admin: Address,
        governance: Address,
        amount: i128,
        reason: Symbol,
    ) -> IdentityBond {
        Self::require_admin_internal(&e, &admin);
        let cfg = emergency::get_config(&e);
        if governance != cfg.governance {
            panic!("not governance");
        }
        if !cfg.enabled {
            panic!("emergency mode disabled");
        }
        if amount <= 0 {
            panic!("amount must be positive");
        }
        admin.require_auth();
        governance.require_auth();
        let key = DataKey::Bond;
        let mut bond: IdentityBond = e
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic!("no bond"));
        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .expect("slashed exceeds bonded");
        if amount > available {
            panic!("insufficient balance for withdrawal");
        }
        let fee_amount = emergency::calculate_fee(amount, cfg.emergency_fee_bps);
        let net_amount = amount.checked_sub(fee_amount).expect("fee exceeds amount");
        let old_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        bond.bonded_amount = bond.bonded_amount.checked_sub(amount).expect("underflow");
        if bond.slashed_amount > bond.bonded_amount {
            panic!("slashed exceeds bonded");
        }
        let new_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        tiered_bond::emit_tier_change_if_needed(&e, &bond.identity, old_tier, new_tier);
        let record_id = emergency::store_record(
            &e,
            bond.identity.clone(),
            amount,
            fee_amount,
            net_amount,
            cfg.treasury.clone(),
            admin,
            governance,
            reason.clone(),
        );
        emergency::emit_emergency_withdrawal_event(
            &e,
            record_id,
            &bond.identity,
            amount,
            fee_amount,
            net_amount,
            &reason,
        );
        e.storage().instance().set(&key, &bond);
        bond
    }

    pub fn get_emergency_config(e: Env) -> emergency::EmergencyConfig {
        emergency::get_config(&e)
    }
    pub fn get_latest_emergency_record_id(e: Env) -> u64 {
        emergency::latest_record_id(&e)
    }
    pub fn get_emergency_record(e: Env, id: u64) -> emergency::EmergencyWithdrawalRecord {
        emergency::get_record(&e, id)
    }

    /// Register an authorized attester (only admin can call).
    pub fn register_attester(e: Env, attester: Address) {
        pausable::require_not_paused(&e);
        let admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("not initialized"));
        admin.require_auth();
        Self::require_admin_internal(&e, &admin);
        add_verifier_role(&e, &admin, &attester);
        e.storage()
            .instance()
            .set(&DataKey::Attester(attester.clone()), &true);
        verifier::register_legacy(&e, &attester);
        e.events()
            .publish((Symbol::new(&e, "attester_registered"),), attester);
    }

    /// Remove an attester's authorization (only admin can call).
    pub fn unregister_attester(e: Env, attester: Address) {
        pausable::require_not_paused(&e);
        let admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("not initialized"));
        admin.require_auth();
        Self::require_admin_internal(&e, &admin);
        remove_verifier_role(&e, &admin, &attester);
        verifier::deactivate_if_exists(&e, &attester, Symbol::new(&e, "admin"));
        e.events()
            .publish((Symbol::new(&e, "attester_unregistered"),), attester);
    }

    /// Check if an address is an authorized attester.
    pub fn is_attester(e: Env, attester: Address) -> bool {
        is_verifier(&e, &attester)
    }

    pub fn set_verifier_stake_requirement(e: Env, admin: Address, min_stake: i128) {
        admin.require_auth();
        Self::require_admin_internal(&e, &admin);
        verifier::set_min_stake(&e, min_stake);
    }
    pub fn get_verifier_stake_requirement(e: Env) -> i128 {
        verifier::get_min_stake(&e)
    }

    pub fn register_verifier(
        e: Env,
        verifier_addr: Address,
        stake_deposit: i128,
    ) -> verifier::VerifierInfo {
        verifier_addr.require_auth();
        Self::with_reentrancy_guard(&e, || {
            verifier::register_with_stake(&e, &verifier_addr, stake_deposit)
        })
    }
    pub fn deactivate_verifier(e: Env, verifier_addr: Address) -> verifier::VerifierInfo {
        verifier_addr.require_auth();
        verifier::deactivate_verifier(&e, &verifier_addr, Symbol::new(&e, "self"))
    }
    pub fn deactivate_verifier_by_admin(
        e: Env,
        admin: Address,
        verifier_addr: Address,
    ) -> verifier::VerifierInfo {
        admin.require_auth();
        Self::require_admin_internal(&e, &admin);
        verifier::deactivate_verifier(&e, &verifier_addr, Symbol::new(&e, "admin"))
    }
    pub fn withdraw_verifier_stake(
        e: Env,
        verifier_addr: Address,
        amount: i128,
    ) -> verifier::VerifierInfo {
        verifier_addr.require_auth();
        Self::with_reentrancy_guard(&e, || verifier::withdraw_stake(&e, &verifier_addr, amount))
    }
    pub fn get_verifier_info(e: Env, verifier_addr: Address) -> Option<verifier::VerifierInfo> {
        verifier::get_verifier_info(&e, &verifier_addr)
    }
    pub fn set_verifier_reputation(
        e: Env,
        admin: Address,
        verifier_addr: Address,
        new_reputation: i128,
    ) {
        admin.require_auth();
        Self::require_admin_internal(&e, &admin);
        verifier::set_reputation(&e, &verifier_addr, new_reputation, Symbol::new(&e, "admin"));
    }

    pub fn set_token(e: Env, admin: Address, token: Address) {
        token_integration::set_token(&e, &admin, &token);
    }
    pub fn set_usdc_token(e: Env, admin: Address, token: Address, network: String) {
        token_integration::set_usdc_token(&e, &admin, &token, &network);
    }
    pub fn get_usdc_token(e: Env) -> Address {
        token_integration::get_token(&e)
    }
    pub fn get_usdc_network(e: Env) -> Option<String> {
        token_integration::get_usdc_network(&e)
    }

    pub fn create_bond(e: Env, identity: Address, amount: i128, duration: u64) -> IdentityBond {
        Self::create_bond_with_rolling(e, identity, amount, duration, false, 0)
    }

    pub fn create_bond_with_rolling(
        e: Env,
        identity: Address,
        amount: i128,
        duration: u64,
        is_rolling: bool,
        notice_period_duration: u64,
    ) -> IdentityBond {
        pausable::require_not_paused(&e);
        validation::validate_bond_amount(amount);
        validation::validate_bond_duration(duration);
        identity.require_auth();
        token_integration::transfer_into_contract(&e, &identity, amount);
        let bond_start = e.ledger().timestamp();
        let _end = bond_start.checked_add(duration).expect("bond end overflow");
        let (fee, net_amount) = fees::calculate_fee(&e, amount);
        if fee > 0 {
            let (treasury_opt, _) = fees::get_config(&e);
            if let Some(treasury) = treasury_opt {
                fees::record_fee(&e, &identity, amount, fee, &treasury);
            }
        }
        let bond = IdentityBond {
            identity: identity.clone(),
            bonded_amount: amount,
            bond_start,
            bond_duration: duration,
            slashed_amount: 0,
            active: true,
            is_rolling,
            withdrawal_requested_at: 0,
            notice_period_duration,
        };
        e.storage().instance().set(&DataKey::Bond, &bond);
        let old_tier = BondTier::Bronze;
        let new_tier = tiered_bond::get_tier_for_amount(net_amount);
        tiered_bond::emit_tier_change_if_needed(&e, &identity, old_tier, new_tier);
        events::emit_bond_created(&e, &identity, amount, duration, is_rolling);
        bond
    }

    /// Return current bond state for an identity (simplified: single bond per contract instance).
    pub fn get_identity_state(e: Env) -> IdentityBond {
        e.storage()
            .instance()
            .get::<_, IdentityBond>(&DataKey::Bond)
            .unwrap_or_else(|| panic!("no bond"))
    }

    /// Add an attestation for a subject.
    ///
    /// Enforces the full permit-like security model:
    /// - `deadline`: must be >= current ledger timestamp (prevents stale replay).
    /// - `contract_id`: must match this contract's address (domain separation).
    /// - `nonce`: must match attester's current nonce, then increments (replay prevention).
    pub fn add_attestation(
        e: Env,
        attester: Address,
        subject: Address,
        attestation_data: String,
        contract_id: Address,
        deadline: u64,
        nonce: u64,
    ) -> Attestation {
        nonce::validate_and_consume(&e, &attester, &contract_id, deadline, nonce);
        attester.require_auth();
        require_verifier(&e, &attester);
        let is_authorized: bool = e
            .storage()
            .instance()
            .get(&DataKey::Attester(attester.clone()))
            .unwrap_or(false);
        if !is_authorized {
            panic!("unauthorized attester");
        }
        let dup_key =
            DataKey::DuplicateCheck(attester.clone(), subject.clone(), attestation_data.clone());
        if e.storage().instance().has(&dup_key) {
            panic!("duplicate attestation");
        }
        e.storage().instance().set(&dup_key, &true);
        let counter_key = DataKey::AttestationCounter;
        let id: u64 = e.storage().instance().get(&counter_key).unwrap_or(0);
        let next_id = id.checked_add(1).expect("attestation counter overflow");
        e.storage().instance().set(&counter_key, &next_id);
        let weight = weighted_attestation::compute_weight(&e, &attester);
        let attestation = Attestation {
            id,
            verifier: attester.clone(),
            identity: subject.clone(),
            attestation_data: attestation_data.clone(),
            timestamp: e.ledger().timestamp(),
            weight,
            revoked: false,
        };
        e.storage()
            .instance()
            .set(&DataKey::Attestation(id), &attestation);
        let subject_key = DataKey::SubjectAttestations(subject.clone());
        let mut attestations: Vec<u64> = e
            .storage()
            .instance()
            .get(&subject_key)
            .unwrap_or(Vec::new(&e));
        attestations.push_back(id);
        e.storage().instance().set(&subject_key, &attestations);
        verifier::record_attestation_issued(&e, &attester, weight);
        e.events().publish(
            (Symbol::new(&e, "attestation_added"), subject),
            (id, attester, attestation_data),
        );
        attestation
    }

    /// Revoke an attestation (only the original attester).
    ///
    /// Same permit-like security model: deadline, domain, and nonce are all validated.
    pub fn revoke_attestation(
        e: Env,
        attester: Address,
        attestation_id: u64,
        contract_id: Address,
        deadline: u64,
        nonce: u64,
    ) {
        nonce::validate_and_consume(&e, &attester, &contract_id, deadline, nonce);
        pausable::require_not_paused(&e);
        attester.require_auth();
        let key = DataKey::Attestation(attestation_id);
        let mut attestation: Attestation = e
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic!("attestation not found"));
        if attestation.verifier != attester {
            panic!("only original attester can revoke");
        }
        if attestation.revoked {
            panic!("attestation already revoked");
        }
        attestation.revoked = true;
        e.storage().instance().set(&key, &attestation);
        verifier::record_attestation_revoked(&e, &attester, attestation.weight);
        e.events().publish(
            (
                Symbol::new(&e, "attestation_revoked"),
                attestation.identity.clone(),
            ),
            (attestation_id, attester),
        );
    }

    /// Get an attestation by ID.
    pub fn get_attestation(e: Env, attestation_id: u64) -> Attestation {
        e.storage()
            .instance()
            .get(&DataKey::Attestation(attestation_id))
            .unwrap_or_else(|| panic!("attestation not found"))
    }
    pub fn get_subject_attestations(e: Env, subject: Address) -> Vec<u64> {
        e.storage()
            .instance()
            .get(&DataKey::SubjectAttestations(subject))
            .unwrap_or(Vec::new(&e))
    }
    pub fn get_subject_attestation_count(e: Env, subject: Address) -> u32 {
        e.storage()
            .instance()
            .get(&DataKey::SubjectAttestationCount(subject))
            .unwrap_or(0)
    }
    pub fn get_nonce(e: Env, identity: Address) -> u64 {
        nonce::get_nonce(&e, &identity)
    }

    pub fn set_attester_stake(e: Env, admin: Address, attester: Address, amount: i128) {
        Self::require_admin_internal(&e, &admin);
        weighted_attestation::set_attester_stake(&e, &attester, amount);
    }
    pub fn set_weight_config(e: Env, admin: Address, multiplier_bps: u32, max_weight: u32) {
        Self::require_admin_internal(&e, &admin);
        weighted_attestation::set_weight_config(&e, multiplier_bps, max_weight);
    }
    pub fn get_weight_config(e: Env) -> (u32, u32) {
        weighted_attestation::get_weight_config(&e)
    }

    pub fn withdraw(e: Env, amount: i128) -> IdentityBond {
        Self::withdraw_bond(e, amount)
    }

    pub fn withdraw_bond(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic!("no bond"));
        if amount < 0 {
            panic!("amount must be non-negative");
        }
        bond.identity.require_auth();
        let now = e.ledger().timestamp();
        let end = bond.bond_start.saturating_add(bond.bond_duration);
        if bond.is_rolling {
            if bond.withdrawal_requested_at == 0 {
                panic!("cooldown window not elapsed; request_withdrawal first");
            }
            if !rolling_bond::can_withdraw_after_notice(
                now,
                bond.withdrawal_requested_at,
                bond.notice_period_duration,
            ) {
                panic!("cooldown window not elapsed; request_withdrawal first");
            }
        } else if now < end {
            panic!("lock-up period not elapsed; use withdraw_early");
        }
        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .expect("slashed exceeds bonded");
        if amount > available {
            panic!("insufficient balance for withdrawal");
        }
        token_integration::transfer_from_contract(&e, &bond.identity, amount);
        let old_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        bond.bonded_amount = bond.bonded_amount.checked_sub(amount).expect("underflow");
        if bond.slashed_amount > bond.bonded_amount {
            panic!("slashed amount exceeds bonded amount");
        }
        let new_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        tiered_bond::emit_tier_change_if_needed(&e, &bond.identity, old_tier, new_tier);
        e.storage().instance().set(&key, &bond);
        events::emit_bond_withdrawn(&e, &bond.identity, amount, bond.bonded_amount);
        bond
    }

    pub fn withdraw_early(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic!("no bond"));
        if amount < 0 {
            panic!("amount must be non-negative");
        }
        bond.identity.require_auth();
        let now = e.ledger().timestamp();
        let end = bond.bond_start.saturating_add(bond.bond_duration);
        if now >= end {
            panic!("use withdraw for post lock-up");
        }
        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .expect("slashed exceeds bonded");
        if amount > available {
            panic!("insufficient balance for withdrawal");
        }
        let (treasury, penalty_bps) = early_exit_penalty::get_config(&e);
        let remaining = end.saturating_sub(now);
        let penalty = early_exit_penalty::calculate_penalty(
            amount,
            remaining,
            bond.bond_duration,
            penalty_bps,
        );
        early_exit_penalty::emit_penalty_event(&e, &bond.identity, amount, penalty, &treasury);
        let net_amount = amount.checked_sub(penalty).expect("penalty exceeds amount");
        token_integration::transfer_from_contract(&e, &bond.identity, net_amount);
        if penalty > 0 {
            token_integration::transfer_from_contract(&e, &treasury, penalty);
        }
        let old_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        bond.bonded_amount = bond.bonded_amount.checked_sub(amount).expect("underflow");
        if bond.slashed_amount > bond.bonded_amount {
            panic!("slashed exceeds bonded");
        }
        let new_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        tiered_bond::emit_tier_change_if_needed(&e, &bond.identity, old_tier, new_tier);
        e.storage().instance().set(&key, &bond);
        bond
    }

    /// Request withdrawal (rolling bonds). Withdrawal allowed after notice period.
    pub fn request_withdrawal(e: Env) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic!("no bond"));
        if !bond.is_rolling {
            panic!("not a rolling bond");
        }
        if bond.withdrawal_requested_at != 0 {
            panic!("withdrawal already requested");
        }
        bond.withdrawal_requested_at = e.ledger().timestamp();
        e.storage().instance().set(&key, &bond);
        e.events().publish(
            (Symbol::new(&e, "withdrawal_requested"),),
            (bond.identity.clone(), bond.withdrawal_requested_at),
        );
        bond
    }

    /// If bond is rolling and period has ended, renew (new period start = now). Emits renewal event.
    pub fn renew_if_rolling(e: Env) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic!("no bond"));
        if !bond.is_rolling {
            return bond;
        }
        let now = e.ledger().timestamp();
        if !rolling_bond::is_period_ended(now, bond.bond_start, bond.bond_duration) {
            return bond;
        }
        rolling_bond::apply_renewal(&mut bond, now);
        e.storage().instance().set(&key, &bond);
        e.events().publish(
            (Symbol::new(&e, "bond_renewed"),),
            (bond.identity.clone(), bond.bond_start, bond.bond_duration),
        );
        bond
    }

    /// Get current tier for the bond's bonded amount.
    pub fn get_tier(e: Env) -> BondTier {
        let bond = Self::get_identity_state(e);
        tiered_bond::get_tier_for_amount(bond.bonded_amount)
    }

    pub fn slash(e: Env, admin: Address, amount: i128) -> IdentityBond {
        admin.require_auth();
        Self::require_admin_internal(&e, &admin);
        if amount < 0 {
            panic!("slash amount must be non-negative");
        }
        slashing::slash_bond(&e, &admin, amount)
    }

    pub fn initialize_governance(
        e: Env,
        admin: Address,
        governors: Vec<Address>,
        quorum_bps: u32,
        min_governors: u32,
    ) {
        pausable::require_not_paused(&e);
        Self::require_admin_internal(&e, &admin);
        governance_approval::initialize_governance(&e, governors, quorum_bps, min_governors);
    }

    /// Top up the bond with additional amount (checks for overflow)
    pub fn top_up(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic!("no bond"));

    pub fn governance_vote(e: Env, voter: Address, proposal_id: u64, approve: bool) {
        pausable::require_not_paused(&e);
        voter.require_auth();
        governance_approval::vote(&e, &voter, proposal_id, approve);
    }

    pub fn governance_delegate(e: Env, governor: Address, to: Address) {
        pausable::require_not_paused(&e);
        governance_approval::delegate(&e, &governor, &to);
    }

    pub fn execute_slash_with_governance(
        e: Env,
        proposer: Address,
        proposal_id: u64,
    ) -> IdentityBond {
        pausable::require_not_paused(&e);
        proposer.require_auth();
        let proposal = governance_approval::get_proposal(&e, proposal_id)
            .unwrap_or_else(|| panic!("proposal not found"));
        if proposal.proposed_by != proposer {
            panic!("only proposer can execute");
        }
        let executed = governance_approval::execute_slash_if_approved(&e, proposal_id);
        if !executed {
            panic!("proposal not approved");
        }
        slashing::slash_bond(&e, &proposer, proposal.amount)
    }

    pub fn set_fee_config(e: Env, admin: Address, treasury: Address, fee_bps: u32) {
        pausable::require_not_paused(&e);
        Self::require_admin_internal(&e, &admin);
        fees::set_config(&e, treasury, fee_bps);
    }
    pub fn get_fee_config(e: Env) -> (Option<Address>, u32) {
        fees::get_config(&e)
    }

    pub fn deposit_fees(e: Env, amount: i128) {
        let key = Symbol::new(&e, "fees");
        let current: i128 = e.storage().instance().get(&key).unwrap_or(0);
        let next = current.checked_add(amount).expect("fee pool overflow");
        e.storage().instance().set(&key, &next);
    }

    pub fn set_callback(e: Env, callback: Address) {
        e.storage()
            .instance()
            .set(&Self::callback_key(&e), &callback);
    }

    pub fn set_bond_token(e: Env, admin: Address, token: Address) {
        Self::require_admin_internal(&e, &admin);
        e.storage().instance().set(&DataKey::BondToken, &token);
    }
    pub fn get_bond_token(e: Env) -> Option<Address> {
        e.storage().instance().get(&DataKey::BondToken)
    }

    pub fn is_locked(e: Env) -> bool {
        Self::check_lock(&e)
    }

    pub fn get_slash_proposal(
        e: Env,
        proposal_id: u64,
    ) -> Option<governance_approval::SlashProposal> {
        governance_approval::get_proposal(&e, proposal_id)
    }
    pub fn get_governance_vote(e: Env, proposal_id: u64, voter: Address) -> Option<bool> {
        governance_approval::get_vote(&e, proposal_id, &voter)
    }
    pub fn get_governors(e: Env) -> Vec<Address> {
        governance_approval::get_governors(&e)
    }
    pub fn get_governance_delegate(e: Env, governor: Address) -> Option<Address> {
        governance_approval::get_delegate(&e, &governor)
    }
    pub fn get_quorum_config(e: Env) -> (u32, u32) {
        governance_approval::get_quorum_config(&e)
    }

    pub fn top_up(e: Env, amount: i128) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond: IdentityBond = e
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| panic!("no bond"));
        if amount <= 0 {
            panic!("amount must be positive");
        }
        bond.identity.require_auth();
        let new_bonded = bond
            .bonded_amount
            .checked_add(amount)
            .expect("top-up overflow");
        validation::validate_bond_amount(new_bonded);
        let old_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        bond.bonded_amount = new_bonded;
        token_integration::transfer_into_contract(&e, &bond.identity, amount);
        let new_tier = tiered_bond::get_tier_for_amount(bond.bonded_amount);
        tiered_bond::emit_tier_change_if_needed(&e, &bond.identity, old_tier, new_tier);
        events::emit_bond_increased(&e, &bond.identity, amount, bond.bonded_amount);
        e.storage().instance().set(&key, &bond);
        bond
    }

    pub fn increase_bond(e: Env, caller: Address, amount: i128) -> IdentityBond {
        caller.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        Self::with_reentrancy_guard(&e, || {
            let key = DataKey::Bond;
            let mut bond = e
                .storage()
                .instance()
                .get::<_, IdentityBond>(&key)
                .unwrap_or_else(|| panic!("no bond"));
            if bond.identity != caller {
                panic!("not bond owner");
            }
            let token_addr: Address = e
                .storage()
                .instance()
                .get(&DataKey::BondToken)
                .unwrap_or_else(|| panic!("bond token not configured"));
            let old_amount = bond.bonded_amount;
            let new_amount = old_amount
                .checked_add(amount)
                .expect("bond increase overflow");
            let token_client = TokenClient::new(&e, &token_addr);
            let contract_address = e.current_contract_address();
            token_client.transfer_from(&contract_address, &caller, &contract_address, &amount);
            let old_tier = tiered_bond::get_tier_for_amount(old_amount);
            let new_tier = tiered_bond::get_tier_for_amount(new_amount);
            bond.bonded_amount = new_amount;
            e.storage().instance().set(&key, &bond);
            tiered_bond::emit_tier_change_if_needed(&e, &bond.identity, old_tier, new_tier);
            e.events().publish(
                (Symbol::new(&e, "bond_increased"), bond.identity.clone()),
                (amount, old_amount, new_amount),
            );
            bond
        })
    }

    pub fn extend_duration(e: Env, additional_duration: u64) -> IdentityBond {
        let key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&key)
            .unwrap_or_else(|| panic!("no bond"));
        bond.identity.require_auth();
        bond.bond_duration = bond
            .bond_duration
            .checked_add(additional_duration)
            .expect("duration overflow");
        let _end = bond
            .bond_start
            .checked_add(bond.bond_duration)
            .expect("bond end overflow");
        e.storage().instance().set(&key, &bond);
        bond
    }

    pub fn submit_evidence(
        e: Env,
        submitter: Address,
        proposal_id: u64,
        hash: String,
        hash_type: EvidenceType,
        description: Option<String>,
    ) -> u64 {
        submitter.require_auth();
        evidence::submit_evidence(&e, &submitter, proposal_id, &hash, &hash_type, &description)
    }
    pub fn get_evidence(e: Env, evidence_id: u64) -> Evidence {
        evidence::get_evidence(&e, evidence_id)
    }
    pub fn get_proposal_evidence(e: Env, proposal_id: u64) -> Vec<u64> {
        evidence::get_proposal_evidence(&e, proposal_id)
    }
    pub fn get_proposal_evidence_details(e: Env, proposal_id: u64) -> Vec<Evidence> {
        evidence::get_proposal_evidence_details(&e, proposal_id)
    }
    pub fn evidence_hash_exists(e: Env, hash: String) -> bool {
        evidence::hash_exists(&e, &hash)
    }
    pub fn get_evidence_count(e: Env) -> u64 {
        evidence::get_evidence_count(&e)
    }

    pub fn create_batch_bonds(e: Env, params_list: Vec<BatchBondParams>) -> BatchBondResult {
        batch::create_batch_bonds(&e, params_list)
    }
    pub fn validate_batch_bonds(e: Env, params_list: Vec<BatchBondParams>) -> bool {
        batch::validate_batch(&e, params_list)
    }
    pub fn get_batch_total_amount(params_list: Vec<BatchBondParams>) -> i128 {
        batch::get_batch_total_amount(&params_list)
    }

    pub fn get_protocol_fee_bps(e: Env) -> u32 {
        parameters::get_protocol_fee_bps(&e)
    }
    pub fn set_protocol_fee_bps(e: Env, admin: Address, value: u32) {
        parameters::set_protocol_fee_bps(&e, &admin, value)
    }
    pub fn get_attestation_fee_bps(e: Env) -> u32 {
        parameters::get_attestation_fee_bps(&e)
    }
    pub fn set_attestation_fee_bps(e: Env, admin: Address, value: u32) {
        parameters::set_attestation_fee_bps(&e, &admin, value)
    }
    pub fn get_withdrawal_cooldown_secs(e: Env) -> u64 {
        parameters::get_withdrawal_cooldown_secs(&e)
    }
    pub fn set_withdrawal_cooldown_secs(e: Env, admin: Address, value: u64) {
        parameters::set_withdrawal_cooldown_secs(&e, &admin, value)
    }
    pub fn get_slash_cooldown_secs(e: Env) -> u64 {
        parameters::get_slash_cooldown_secs(&e)
    }
    pub fn set_slash_cooldown_secs(e: Env, admin: Address, value: u64) {
        parameters::set_slash_cooldown_secs(&e, &admin, value)
    }
    pub fn get_bronze_threshold(e: Env) -> i128 {
        parameters::get_bronze_threshold(&e)
    }
    pub fn set_bronze_threshold(e: Env, admin: Address, value: i128) {
        parameters::set_bronze_threshold(&e, &admin, value)
    }
    pub fn get_silver_threshold(e: Env) -> i128 {
        parameters::get_silver_threshold(&e)
    }
    pub fn set_silver_threshold(e: Env, admin: Address, value: i128) {
        parameters::set_silver_threshold(&e, &admin, value)
    }
    pub fn get_gold_threshold(e: Env) -> i128 {
        parameters::get_gold_threshold(&e)
    }
    pub fn set_gold_threshold(e: Env, admin: Address, value: i128) {
        parameters::set_gold_threshold(&e, &admin, value)
    }
    pub fn get_platinum_threshold(e: Env) -> i128 {
        parameters::get_platinum_threshold(&e)
    }
    pub fn set_platinum_threshold(e: Env, admin: Address, value: i128) {
        parameters::set_platinum_threshold(&e, &admin, value)
    }

    pub fn withdraw_bond_full(e: Env, identity: Address) -> i128 {
        identity.require_auth();
        Self::acquire_lock(&e);
        let bond_key = DataKey::Bond;
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic!("no bond"));
        if bond.identity != identity {
            Self::release_lock(&e);
            panic!("not bond owner");
        }
        if !bond.active {
            Self::release_lock(&e);
            panic!("bond not active");
        }
        let withdraw_amount = bond.bonded_amount - bond.slashed_amount;
        let updated = IdentityBond {
            identity: identity.clone(),
            bonded_amount: 0,
            bond_start: bond.bond_start,
            bond_duration: bond.bond_duration,
            slashed_amount: bond.slashed_amount,
            active: false,
            is_rolling: bond.is_rolling,
            withdrawal_requested_at: bond.withdrawal_requested_at,
            notice_period: bond.notice_period,
        };
        e.storage().instance().set(&bond_key, &updated);
        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_withdraw");
            let args: Vec<Val> = Vec::from_array(&e, [withdraw_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }
        Self::release_lock(&e);
        withdraw_amount
    }

    pub fn slash_bond(e: Env, admin: Address, slash_amount: i128) -> i128 {
        admin.require_auth();
        Self::acquire_lock(&e);
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("no admin"));
        if stored_admin != admin {
            Self::release_lock(&e);
            panic!("not admin");
        }
        let bond_key = DataKey::Bond;
        let bond: IdentityBond = e
            .storage()
            .instance()
            .get(&bond_key)
            .unwrap_or_else(|| panic!("no bond"));
        if !bond.active {
            Self::release_lock(&e);
            panic!("bond not active");
        }
        let new_slashed = bond
            .slashed_amount
            .checked_add(slash_amount)
            .expect("slashing overflow");
        if new_slashed > bond.bonded_amount {
            Self::release_lock(&e);
            panic!("slash exceeds bond");
        }
        let updated = IdentityBond {
            identity: bond.identity.clone(),
            bonded_amount: bond.bonded_amount,
            bond_start: bond.bond_start,
            bond_duration: bond.bond_duration,
            slashed_amount: new_slashed,
            active: bond.active,
            is_rolling: bond.is_rolling,
            withdrawal_requested_at: bond.withdrawal_requested_at,
            notice_period: bond.notice_period,
        };
        e.storage().instance().set(&bond_key, &updated);
        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_slash");
            let args: Vec<Val> = Vec::from_array(&e, [slash_amount.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }
        Self::release_lock(&e);
        new_slashed
    }

    pub fn collect_fees(e: Env, admin: Address) -> i128 {
        admin.require_auth();
        Self::acquire_lock(&e);
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("no admin"));
        if stored_admin != admin {
            Self::release_lock(&e);
            panic!("not admin");
        }
        let fee_key = Symbol::new(&e, "fees");
        let fees: i128 = e.storage().instance().get(&fee_key).unwrap_or(0);
        e.storage().instance().set(&fee_key, &0_i128);
        let cb_key = Symbol::new(&e, "callback");
        if let Some(cb_addr) = e.storage().instance().get::<_, Address>(&cb_key) {
            let fn_name = Symbol::new(&e, "on_collect");
            let args: Vec<Val> = Vec::from_array(&e, [fees.into_val(&e)]);
            e.invoke_contract::<Val>(&cb_addr, &fn_name, args);
        }
        Self::release_lock(&e);
        fees
    }

    pub fn set_cooldown_period(e: Env, admin: Address, period: u64) {
        let stored_admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("not initialized"));
        if admin != stored_admin {
            panic!("not admin");
        }
        admin.require_auth();
        let old = cooldown::get_cooldown_period(&e);
        cooldown::set_cooldown_period(&e, period);
        cooldown::emit_cooldown_period_updated(&e, old, period);
    }
    pub fn get_cooldown_period(e: Env) -> u64 {
        cooldown::get_cooldown_period(&e)
    }

    pub fn request_cooldown_withdrawal(
        e: Env,
        requester: Address,
        amount: i128,
    ) -> CooldownRequest {
        requester.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&DataKey::Bond)
            .unwrap_or_else(|| panic!("no bond"));
        if bond.identity != requester {
            panic!("requester is not the bond holder");
        }
        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .expect("slashed exceeds bonded");
        if amount > available {
            panic!("amount exceeds available balance");
        }
        let req_key = DataKey::CooldownReq(requester.clone());
        if e.storage().instance().has(&req_key) {
            panic!("cooldown request already pending");
        }
        let request = CooldownRequest {
            requester: requester.clone(),
            amount,
            requested_at: e.ledger().timestamp(),
        };
        e.storage().instance().set(&req_key, &request);
        cooldown::emit_cooldown_requested(&e, &requester, amount);
        request
    }

    pub fn execute_cooldown_withdrawal(e: Env, requester: Address) -> IdentityBond {
        requester.require_auth();
        let req_key = DataKey::CooldownReq(requester.clone());
        let request: CooldownRequest = e
            .storage()
            .instance()
            .get(&req_key)
            .unwrap_or_else(|| panic!("no cooldown request"));
        let period = cooldown::get_cooldown_period(&e);
        let now = e.ledger().timestamp();
        if !cooldown::can_withdraw(now, request.requested_at, period) {
            panic!("cooldown period has not elapsed");
        }
        let bond_key = DataKey::Bond;
        let mut bond = e
            .storage()
            .instance()
            .get::<_, IdentityBond>(&bond_key)
            .unwrap_or_else(|| panic!("no bond"));
        let available = bond
            .bonded_amount
            .checked_sub(bond.slashed_amount)
            .expect("slashed exceeds bonded");
        if request.amount > available {
            panic!("insufficient balance for withdrawal");
        }
        bond.bonded_amount = bond
            .bonded_amount
            .checked_sub(request.amount)
            .expect("underflow");
        if bond.slashed_amount > bond.bonded_amount {
            panic!("slashed exceeds bonded after withdrawal");
        }
        e.storage().instance().set(&bond_key, &bond);
        e.storage().instance().remove(&req_key);
        cooldown::emit_cooldown_executed(&e, &requester, request.amount);
        bond
    }

    pub fn cancel_cooldown(e: Env, requester: Address) {
        requester.require_auth();
        let req_key = DataKey::CooldownReq(requester.clone());
        if !e.storage().instance().has(&req_key) {
            panic!("no cooldown request to cancel");
        }
        e.storage().instance().remove(&req_key);
        cooldown::emit_cooldown_cancelled(&e, &requester);
    }

    pub fn get_cooldown_request(e: Env, requester: Address) -> CooldownRequest {
        e.storage()
            .instance()
            .get(&DataKey::CooldownReq(requester))
            .unwrap_or_else(|| panic!("no cooldown request"))
    }
}

#[contractimpl]
impl CredenceBond {
    pub fn is_paused(e: Env) -> bool {
        pausable::is_paused(&e)
    }
    pub fn pause(e: Env, caller: Address) -> Option<u64> {
        pausable::pause(&e, &caller)
    }
    pub fn unpause(e: Env, caller: Address) -> Option<u64> {
        pausable::unpause(&e, &caller)
    }
    pub fn set_pause_signer(e: Env, admin: Address, signer: Address, enabled: bool) {
        pausable::set_pause_signer(&e, &admin, &signer, enabled)
    }
    pub fn set_pause_threshold(e: Env, admin: Address, threshold: u32) {
        pausable::set_pause_threshold(&e, &admin, threshold)
    }
    pub fn approve_pause_proposal(e: Env, signer: Address, proposal_id: u64) {
        pausable::approve_pause_proposal(&e, &signer, proposal_id)
    }
    pub fn execute_pause_proposal(e: Env, proposal_id: u64) {
        pausable::execute_pause_proposal(&e, proposal_id)
    }
}

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod integration;
#[cfg(test)]
mod security;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_access_control;
#[cfg(test)]
mod test_attestation;
#[cfg(test)]
mod test_attestation_types;
#[cfg(test)]
mod test_batch;
#[cfg(test)]
mod test_cooldown;
#[cfg(test)]
mod test_duration_validation;
#[cfg(test)]
mod test_early_exit_penalty;
#[cfg(test)]
mod test_emergency;
#[cfg(test)]
mod test_events;
#[cfg(test)]
mod test_evidence;
#[cfg(test)]
mod test_fees;
#[cfg(test)]
mod test_governance_approval;
#[cfg(test)]
mod test_helpers;
#[cfg(test)]
mod test_increase_bond;
#[cfg(test)]
mod test_math;
#[cfg(test)]
mod test_parameters;
#[cfg(test)]
mod test_pausable;
#[cfg(test)]
mod test_reentrancy;
#[cfg(test)]
mod test_replay_prevention;
#[cfg(test)]
mod test_rolling_bond;
#[cfg(test)]
mod test_slashing;
#[cfg(test)]
mod test_tiered_bond;
#[cfg(test)]
mod test_validation;
#[cfg(test)]
mod test_verifier;
#[cfg(test)]
mod test_weighted_attestation;
#[cfg(test)]
mod test_withdraw_bond;
#[cfg(test)]
mod token_integration_test;
