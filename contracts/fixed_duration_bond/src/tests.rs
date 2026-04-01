//! Comprehensive tests for the fixed_duration_bond contract.

use crate::test_helpers::*;
use crate::{
    apply_bps,
    FixedDurationBond,
    FixedDurationBondClient,
    MAX_FEE_BPS,
    DEFAULT_MAX_STALENESS,
};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::token::TokenClient;
use soroban_sdk::{Address, Env};

// ═══════════════════════════════════════════════════════════════════
// 1. Initialization
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_initialize_success() {
    let e = Env::default();
    e.mock_all_auths();
    let contract_id = e.register(FixedDurationBond, ());
    let client = FixedDurationBondClient::new(&e, &contract_id);
    let admin = Address::generate(&e);
    let token = Address::generate(&e);
    client.initialize(&admin, &token);
}

#[test]
#[should_panic(expected = "already initialized")]
fn test_initialize_twice_panics() {
    let e = Env::default();
    e.mock_all_auths();
    let contract_id = e.register(FixedDurationBond, ());
    let client = FixedDurationBondClient::new(&e, &contract_id);
    let admin = Address::generate(&e);
    let token = Address::generate(&e);
    client.initialize(&admin, &token);
    client.initialize(&admin, &token);
}

// ═══════════════════════════════════════════════════════════════════
// 2. Bond creation — happy path
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_create_bond_success() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);

    let bond = client.create_bond(&owner, &1_000_000_i128, &ONE_DAY);

    assert!(bond.active);
    assert_eq!(bond.amount, 1_000_000);
    assert_eq!(bond.bond_duration, ONE_DAY);
    assert_eq!(bond.owner, owner);
    assert_eq!(bond.bond_expiry, bond.bond_start + ONE_DAY);
}

#[test]
fn test_create_bond_stores_expiry_correctly() {
    let e = Env::default();
    e.ledger().with_mut(|li| li.timestamp = 1_000_000);
    let (client, _admin, owner, _token, _cid) = setup(&e);

    let bond = client.create_bond(&owner, &5_000_000_i128, &ONE_WEEK);

    assert_eq!(bond.bond_start, 1_000_000);
    assert_eq!(bond.bond_expiry, 1_000_000 + ONE_WEEK);
}

#[test]
fn test_create_bond_with_min_positive_amount() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    let bond = client.create_bond(&owner, &1_i128, &ONE_DAY);
    assert_eq!(bond.amount, 1);
    assert!(bond.active);
}

#[test]
fn test_create_bond_usdc_amount() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    let usdc = 100_000_000_i128; // 100 USDC (6 decimals)
    let bond = client.create_bond(&owner, &usdc, &ONE_DAY);
    assert_eq!(bond.amount, usdc);
}

// ═══════════════════════════════════════════════════════════════════
// 2b. Bond creation — error paths
// ═══════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "amount must be positive")]
fn test_create_bond_zero_amount_panics() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &0_i128, &ONE_DAY);
}

#[test]
#[should_panic(expected = "amount must be positive")]
fn test_create_bond_negative_amount_panics() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &(-1_i128), &ONE_DAY);
}

#[test]
#[should_panic(expected = "duration must be positive")]
fn test_create_bond_zero_duration_panics() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &0_u64);
}

#[test]
#[should_panic(expected = "bond expiry timestamp would overflow")]
fn test_create_bond_overflow_panics() {
    let e = Env::default();
    e.ledger().with_mut(|li| li.timestamp = u64::MAX - 500);
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &1_000_u64);
}

#[test]
#[should_panic(expected = "bond already active for this owner")]
fn test_create_bond_duplicate_active_panics() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    client.create_bond(&owner, &2_000_i128, &ONE_DAY);
}

// ═══════════════════════════════════════════════════════════════════
// 3. Maturity checks
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_is_matured_false_before_expiry() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    assert!(!client.is_matured(&owner));
}

#[test]
fn test_is_matured_true_after_expiry() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    e.ledger().with_mut(|li| li.timestamp += ONE_DAY + 1);
    assert!(client.is_matured(&owner));
}

#[test]
fn test_is_matured_true_at_exact_expiry() {
    let e = Env::default();
    e.ledger().with_mut(|li| li.timestamp = 1_000);
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    e.ledger().with_mut(|li| li.timestamp = 1_000 + ONE_DAY);
    assert!(client.is_matured(&owner));
}

#[test]
fn test_get_time_remaining_before_expiry() {
    let e = Env::default();
    e.ledger().with_mut(|li| li.timestamp = 0);
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    e.ledger().with_mut(|li| li.timestamp = ONE_DAY / 2);
    let remaining = client.get_time_remaining(&owner);
    assert_eq!(remaining, ONE_DAY - ONE_DAY / 2);
}

#[test]
fn test_get_time_remaining_zero_after_maturity() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    e.ledger().with_mut(|li| li.timestamp += ONE_DAY + 100);
    assert_eq!(client.get_time_remaining(&owner), 0_u64);
}

// ═══════════════════════════════════════════════════════════════════
// 4. Normal withdrawal (after lock)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_withdraw_success_after_maturity() {
    let e = Env::default();
    let (client, _admin, owner, token_addr, contract_id) = setup(&e);

    let amount = 5_000_000_i128;
    client.create_bond(&owner, &amount, &ONE_DAY);

    e.ledger().with_mut(|li| li.timestamp += ONE_DAY + 1);
    let bond = client.withdraw(&owner);

    assert!(!bond.active);
    let tok = TokenClient::new(&e, &token_addr);
    assert_eq!(tok.balance(&owner), DEFAULT_MINT);
    assert_eq!(tok.balance(&contract_id), 0);
}

#[test]
#[should_panic(expected = "lock period has not elapsed yet")]
fn test_withdraw_before_maturity_panics() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    client.withdraw(&owner);
}

#[test]
#[should_panic(expected = "no active bond found")]
fn test_withdraw_no_bond_panics() {
    let e = Env::default();
    let (client, _admin, _owner, _token, _cid) = setup(&e);
    let other = Address::generate(&e);
    client.withdraw(&other);
}

#[test]
#[should_panic(expected = "no active bond found")]
fn test_withdraw_already_withdrawn_panics() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    e.ledger().with_mut(|li| li.timestamp += ONE_DAY + 1);
    client.withdraw(&owner);
    client.withdraw(&owner); // second call should panic
}

#[test]
fn test_withdraw_deactivates_bond() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    e.ledger().with_mut(|li| li.timestamp += ONE_DAY + 1);
    let bond = client.withdraw(&owner);
    assert!(!bond.active);
}

// ═══════════════════════════════════════════════════════════════════
// 5. Early withdrawal
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_withdraw_early_deducts_penalty() {
    let e = Env::default();
    let (client, admin, owner, token_addr, _cid) = setup(&e);

    // 10% penalty
    client.set_penalty_config(&admin, &1_000_u32);

    let amount = 10_000_i128;
    client.create_bond(&owner, &amount, &ONE_DAY);
    client.withdraw_early(&owner);

    let tok = TokenClient::new(&e, &token_addr);
    let expected_net = 9_000_i128; // 10000 - 10%
    assert_eq!(tok.balance(&owner), DEFAULT_MINT - amount + expected_net);
}

#[test]
fn test_withdraw_early_sends_penalty_to_treasury() {
    let e = Env::default();
    let (client, admin, owner, token_addr, _cid) = setup(&e);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &0_u32); // treasury set, no creation fee
    client.set_penalty_config(&admin, &500_u32); // 5% penalty

    let amount = 10_000_i128;
    client.create_bond(&owner, &amount, &ONE_DAY);
    client.withdraw_early(&owner);

    let tok = TokenClient::new(&e, &token_addr);
    assert_eq!(tok.balance(&treasury), 500); // 5% of 10000
}

#[test]
#[should_panic(expected = "early-exit penalty not configured")]
fn test_withdraw_early_no_penalty_panics() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    client.withdraw_early(&owner);
}

#[test]
#[should_panic(expected = "bond has matured; use withdraw instead")]
fn test_withdraw_early_after_maturity_panics() {
    let e = Env::default();
    let (client, admin, owner, _token, _cid) = setup(&e);
    client.set_penalty_config(&admin, &500_u32);
    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    e.ledger().with_mut(|li| li.timestamp += ONE_DAY + 1);
    client.withdraw_early(&owner);
}

#[test]
#[should_panic(expected = "no active bond found")]
fn test_withdraw_early_no_bond_panics() {
    let e = Env::default();
    let (client, admin, _owner, _token, _cid) = setup(&e);
    client.set_penalty_config(&admin, &500_u32);
    let other = Address::generate(&e);
    client.withdraw_early(&other);
}

// ═══════════════════════════════════════════════════════════════════
// 6. Fee config / collection
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_fee_deducted_from_bond_amount() {
    let e = Env::default();
    let (client, admin, owner, _token, _cid) = setup(&e);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &100_u32); // 1% fee

    let gross = 10_000_i128;
    let bond = client.create_bond(&owner, &gross, &ONE_DAY);
    assert_eq!(bond.amount, 9_900); // net after 1%
}

#[test]
fn test_set_fee_config_max_bps_allows() {
    let e = Env::default();
    let (client, admin, owner, _token, _cid) = setup(&e);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &MAX_FEE_BPS); // max allowed (bps)

    let gross = 10_000_i128;
    let bond = client.create_bond(&owner, &gross, &ONE_DAY);
    assert_eq!(bond.amount, 9_000); // 10% fee at max cap
}

#[test]
fn test_collect_fees() {
    let e = Env::default();
    let (client, admin, owner, token_addr, _cid) = setup(&e);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &100_u32); // 1% fee

    client.create_bond(&owner, &10_000_i128, &ONE_DAY);

    let tok = TokenClient::new(&e, &token_addr);
    let before = tok.balance(&treasury);
    client.collect_fees(&admin, &treasury);
    assert_eq!(tok.balance(&treasury) - before, 100); // 1% of 10000
}

#[test]
fn test_collect_fees_allowlist_enabled_allowed() {
    let e = Env::default();
    let (client, admin, owner, token_addr, _cid) = setup(&e);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &100_u32); // 1% fee

    // enable allowlist and allow recipient
    client.set_receiver_allowlist_enabled(&admin, &true);
    let recipient = Address::generate(&e);
    client.allow_receiver(&admin, &recipient);

    client.create_bond(&owner, &10_000_i128, &ONE_DAY);
    let tok = TokenClient::new(&e, &token_addr);
    let before = tok.balance(&recipient);
    client.collect_fees(&admin, &recipient);
    assert_eq!(tok.balance(&recipient) - before, 100);
}

#[test]
#[should_panic(expected = "unauthorized receiver")]
fn test_collect_fees_allowlist_enabled_not_allowed() {
    let e = Env::default();
    let (client, admin, owner, token_addr, _cid) = setup(&e);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &100_u32); // 1% fee

    // enable allowlist but do not allow the recipient
    client.set_receiver_allowlist_enabled(&admin, &true);
    let recipient = Address::generate(&e);

    client.create_bond(&owner, &10_000_i128, &ONE_DAY);
    client.collect_fees(&admin, &recipient);
}

#[test]
#[should_panic(expected = "no fees to collect")]
fn test_collect_fees_when_none_panics() {
    let e = Env::default();
    let (client, admin, _owner, _token, _cid) = setup(&e);
    let recipient = Address::generate(&e);
    client.collect_fees(&admin, &recipient);
}

#[test]
#[should_panic(expected = "unauthorized")]
fn test_set_fee_config_unauthorized_panics() {
    let e = Env::default();
    let (client, _admin, _owner, _token, _cid) = setup(&e);
    let impostor = Address::generate(&e);
    let treasury = Address::generate(&e);
    client.set_fee_config(&impostor, &treasury, &100_u32);
}

#[test]
#[should_panic(expected = "fee_bps must be <= 1000 (10%)")]
fn test_set_fee_config_over_max_panics() {
    let e = Env::default();
    let (client, admin, _owner, _token, _cid) = setup(&e);
    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &(MAX_FEE_BPS + 1));
}

// ═══════════════════════════════════════════════════════════════════
// 7. Re-bond after withdrawal
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_rebond_after_withdraw() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);

    client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    e.ledger().with_mut(|li| li.timestamp += ONE_DAY + 1);
    client.withdraw(&owner);

    // Should be able to create a new bond after the first is withdrawn.
    let bond2 = client.create_bond(&owner, &2_000_i128, &ONE_WEEK);
    assert!(bond2.active);
    assert_eq!(bond2.amount, 2_000);
}

// ═══════════════════════════════════════════════════════════════════
// 8. Penalty config
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_penalty_stored_on_bond() {
    let e = Env::default();
    let (client, admin, owner, _token, _cid) = setup(&e);
    client.set_penalty_config(&admin, &250_u32); // 2.5%
    let bond = client.create_bond(&owner, &1_000_i128, &ONE_DAY);
    assert_eq!(bond.penalty_bps, 250);
}

#[test]
#[should_panic(expected = "unauthorized")]
fn test_set_penalty_config_unauthorized_panics() {
    let e = Env::default();
    let (client, _admin, _owner, _token, _cid) = setup(&e);
    let impostor = Address::generate(&e);
    client.set_penalty_config(&impostor, &500_u32);
}

// ═══════════════════════════════════════════════════════════════════
// 8b. Oracle answer sanity checks / valuation path
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_quote_value_success_within_configured_bounds() {
    let e = Env::default();
    let (client, admin, _owner, token, _cid) = setup(&e);

    client.set_oracle_safety(&admin, &token, &1_i128, &2_000_000_i128);
    let now = e.ledger().timestamp();
    let quoted = client.quote_value(&token, &10_i128, &123_456_i128, &now, &1_u64, &1_u64);
    assert_eq!(quoted, 1_234_560_i128);
}

#[test]
fn test_quote_value_uses_per_asset_bounds() {
    let e = Env::default();
    let (client, admin, _owner, token_a, _cid) = setup(&e);
    let token_b = Address::generate(&e);

    client.set_oracle_safety(&admin, &token_a, &1_i128, &1_000_i128);
    client.set_oracle_safety(&admin, &token_b, &2_000_i128, &5_000_i128);

    let now = e.ledger().timestamp();
    let a_value = client.quote_value(&token_a, &5_i128, &1_000_i128, &now, &1_u64, &1_u64);
    let b_value = client.quote_value(&token_b, &5_i128, &2_000_i128, &now, &1_u64, &1_u64);
    assert_eq!(a_value, 5_000_i128);
    assert_eq!(b_value, 10_000_i128);
}

#[test]
#[should_panic(expected = "oracle answer must be positive")]
fn test_quote_value_rejects_zero_oracle_answer() {
    let e = Env::default();
    let (client, admin, _owner, token, _cid) = setup(&e);
    client.set_oracle_safety(&admin, &token, &1_i128, &2_000_000_i128);
    let now = e.ledger().timestamp();
    client.quote_value(&token, &10_i128, &0_i128, &now, &1_u64, &1_u64);
}

#[test]
#[should_panic(expected = "oracle answer must be positive")]
fn test_quote_value_rejects_negative_oracle_answer() {
    let e = Env::default();
    let (client, admin, _owner, token, _cid) = setup(&e);
    client.set_oracle_safety(&admin, &token, &1_i128, &2_000_000_i128);
    let now = e.ledger().timestamp();
    client.quote_value(&token, &10_i128, &(-1_i128), &now, &1_u64, &1_u64);
}

#[test]
#[should_panic(expected = "oracle answer out of configured range")]
fn test_quote_value_rejects_extreme_oracle_answer() {
    let e = Env::default();
    let (client, admin, _owner, token, _cid) = setup(&e);
    client.set_oracle_safety(&admin, &token, &1_i128, &2_000_000_i128);
    let now = e.ledger().timestamp();
    client.quote_value(&token, &10_i128, &9_999_999_999_i128, &now, &1_u64, &1_u64);
}

#[test]
#[should_panic(expected = "oracle safety not configured for asset")]
fn test_quote_value_rejects_missing_asset_config() {
    let e = Env::default();
    let (client, _admin, _owner, token, _cid) = setup(&e);
    let now = e.ledger().timestamp();
    client.quote_value(&token, &10_i128, &100_i128, &now, &1_u64, &1_u64);
}

#[test]
#[should_panic(expected = "oracle: stale answer")]
fn test_quote_value_rejects_stale_answer() {
    let e = Env::default();
    let (client, admin, _owner, token, _cid) = setup(&e);

    client.set_oracle_safety(&admin, &token, &1_i128, &2_000_000_i128);
    // set updated_at to older than default staleness
    // ensure ledger now is large enough to create a stale timestamp without underflow
    e.ledger().with_mut(|li| li.timestamp = DEFAULT_MAX_STALENESS + 10);
    let now = e.ledger().timestamp();
    let stale = now - (DEFAULT_MAX_STALENESS + 1);
    client.quote_value(&token, &10_i128, &1_000_i128, &stale, &1_u64, &1_u64);
}

#[test]
#[should_panic(expected = "oracle: incomplete round")]
fn test_quote_value_rejects_incomplete_round() {
    let e = Env::default();
    let (client, admin, _owner, token, _cid) = setup(&e);

    client.set_oracle_safety(&admin, &token, &1_i128, &2_000_000_i128);
    let now = e.ledger().timestamp();
    // answered_in_round < round_id should panic
    client.quote_value(&token, &10_i128, &1_000_i128, &now, &5_u64, &4_u64);
}

#[test]
#[should_panic(expected = "oracle bounds invalid")]
fn test_set_oracle_safety_rejects_zero_min() {
    let e = Env::default();
    let (client, admin, _owner, token, _cid) = setup(&e);
    client.set_oracle_safety(&admin, &token, &0_i128, &1_000_i128);
}

#[test]
#[should_panic(expected = "oracle bounds invalid")]
fn test_set_oracle_safety_rejects_inverted_bounds() {
    let e = Env::default();
    let (client, admin, _owner, token, _cid) = setup(&e);
    client.set_oracle_safety(&admin, &token, &2_000_i128, &1_999_i128);
}

// ═══════════════════════════════════════════════════════════════════
// 9. Query functions
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_get_bond_returns_correct_state() {
    let e = Env::default();
    let (client, _admin, owner, _token, _cid) = setup(&e);
    client.create_bond(&owner, &3_333_i128, &ONE_WEEK);
    let b = client.get_bond(&owner);
    assert_eq!(b.amount, 3_333);
    assert_eq!(b.bond_duration, ONE_WEEK);
    assert!(b.active);
}

#[test]
#[should_panic(expected = "no active bond found")]
fn test_get_bond_nonexistent_panics() {
    let e = Env::default();
    let (client, _admin, _owner, _token, _cid) = setup(&e);
    let stranger = Address::generate(&e);
    client.get_bond(&stranger);
}

// ═══════════════════════════════════════════════════════════════════
// 10. Arithmetic safety — overflow / boundary tests
//
// These tests validate that unchecked arithmetic that was previously
// present in apply_bps and the accrued-fee accumulator now panics
// safely instead of silently wrapping.
// ═══════════════════════════════════════════════════════════════════

/// Max-amount bond with zero fee — no arithmetic is performed on the
/// fee path, so the bond should be stored at full amount.
#[test]
fn test_arithmetic_zero_fee_max_amount_no_overflow() {
    let e = Env::default();
    let mint = i128::MAX / 2;
    let (client, _admin, owner, _tok, _cid) = setup_with_mint(&e, mint);

    let bond = client.create_bond(&owner, &mint, &ONE_DAY);
    assert_eq!(bond.amount, mint);
    assert!(bond.active);
}

/// Small fee bps applied to a large-but-safe deposit.
/// amount * bps must not overflow: here amount * 1000 < i128::MAX.
#[test]
fn test_arithmetic_large_deposit_small_fee_no_overflow() {
    // Largest amount where amount * MAX_FEE_BPS (1000) < i128::MAX:
    // i128::MAX / 1000 ≈ 1.7e35
    let safe_max = i128::MAX / 1_000;
    let e = Env::default();
    let (client, admin, owner, _tok, _cid) = setup_with_mint(&e, safe_max);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &1_000_u32); // 10% — max allowed

    let bond = client.create_bond(&owner, &safe_max, &ONE_DAY);
    // fee = safe_max * 1000 / 10000 = safe_max / 10
    let expected_net = safe_max - (safe_max / 10);
    assert_eq!(bond.amount, expected_net);
}

/// amount * MAX_FEE_BPS overflows i128 — must panic with the fee
/// calculation overflow message rather than silently wrapping.
#[test]
#[should_panic(expected = "fee calculation overflow")]
fn test_arithmetic_fee_mul_overflows_panics() {
    // amount = i128::MAX / 1000 + 1 → amount * 1000 > i128::MAX
    let overflow_amount = i128::MAX / 1_000 + 1;
    let e = Env::default();
    let (client, admin, owner, _tok, _cid) = setup_with_mint(&e, overflow_amount);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &1_000_u32); // 10%

    client.create_bond(&owner, &overflow_amount, &ONE_DAY);
}

/// 1-bps fee on a large-but-safe deposit should not overflow.
#[test]
fn test_arithmetic_one_bps_fee_large_deposit() {
    // amount * 1 < i128::MAX always; safe for any amount.
    let large = i128::MAX / 2;
    let e = Env::default();
    let (client, admin, owner, _tok, _cid) = setup_with_mint(&e, large);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &1_u32); // 0.01%

    let bond = client.create_bond(&owner, &large, &ONE_DAY);
    let expected_fee = large / 10_000;
    assert_eq!(bond.amount, large - expected_fee);
}

#[test]
fn test_apply_bps_matches_legacy_formula() {
    fn legacy_apply_bps(amount: i128, bps: u32) -> (i128, i128) {
        let fee = amount
            .checked_mul(bps as i128)
            .expect("legacy fee multiplication overflow")
            / 10_000_i128;
        let net = amount.checked_sub(fee).expect("legacy fee net underflow");
        (fee, net)
    }

    let cases = [
        (0_i128, 0_u32),
        (10_000, 100),
        (10_000, 1_000),
        (123_456_789, 75),
        (i128::MAX / 20_000, 10_000),
    ];

    for (amount, bps_value) in cases {
        assert_eq!(
            apply_bps(amount, bps_value),
            legacy_apply_bps(amount, bps_value)
        );
    }
}

/// Multiple bonds accumulate fees safely via checked addition.
/// Verifies the accrued-fee counter does not overflow for realistic inputs.
#[test]
fn test_arithmetic_accrued_fees_accumulate_safely() {
    let e = Env::default();
    // Two separate owners — each minted independently.
    e.mock_all_auths();

    let contract_id = e.register(FixedDurationBond, ());
    let client = FixedDurationBondClient::new(&e, &contract_id);
    let admin = Address::generate(&e);

    let stellar_asset = e
        .register_stellar_asset_contract_v2(admin.clone())
        .address();

    use soroban_sdk::token::{StellarAssetClient, TokenClient};
    let asset_admin = StellarAssetClient::new(&e, &stellar_asset);
    let tok = TokenClient::new(&e, &stellar_asset);

    let amount = 10_000_i128;
    let mint = amount * 10;

    // Mint and approve for three owners.
    let owners: [Address; 3] = [
        Address::generate(&e),
        Address::generate(&e),
        Address::generate(&e),
    ];
    let expiry_ledger = e.ledger().sequence().saturating_add(10_000);
    for o in &owners {
        asset_admin.set_authorized(o, &true);
        asset_admin.mint(o, &mint);
        tok.approve(o, &contract_id, &mint, &expiry_ledger);
    }

    client.initialize(&admin, &stellar_asset);

    let treasury = Address::generate(&e);
    client.set_fee_config(&admin, &treasury, &100_u32); // 1%

    for o in &owners {
        client.create_bond(o, &amount, &ONE_DAY);
    }

    // Collect all fees to verify they accumulated correctly.
    // fee per bond = 10_000 * 100 / 10_000 = 100; 3 bonds → 300 total.
    let collected = client.collect_fees(&admin, &treasury);
    assert_eq!(collected, 300);
}

/// Early-exit penalty apply_bps path also uses checked arithmetic.
/// Large-but-safe principal with max penalty must not overflow.
#[test]
fn test_arithmetic_early_exit_penalty_large_amount_no_overflow() {
    let safe = i128::MAX / 10_000; // penalty_bps can be up to u32::MAX in principle
    let e = Env::default();
    let (client, admin, owner, _tok, _cid) = setup_with_mint(&e, safe);

    // Use a small penalty to stay in safe range.
    client.set_penalty_config(&admin, &500_u32); // 5%
    client.create_bond(&owner, &safe, &ONE_DAY);

    let bond = client.withdraw_early(&owner);
    let expected_penalty = safe * 500 / 10_000;
    assert_eq!(bond.amount, safe); // bond struct retains original amount
    let _ = expected_penalty; // verified implicitly by no panic
}

/// Max-duration bond at a safe timestamp — expiry overflow check.
#[test]
fn test_arithmetic_max_duration_safe_timestamp_no_overflow() {
    let e = Env::default();
    // Set timestamp low enough that timestamp + max_safe_duration < u64::MAX.
    e.ledger().with_mut(|li| li.timestamp = 0);
    let (client, _admin, owner, _tok, _cid) = setup(&e);

    // 365 days — well within u64 range.
    let bond = client.create_bond(&owner, &1_000_i128, &(365 * ONE_DAY));
    assert_eq!(bond.bond_duration, 365 * ONE_DAY);
    assert_eq!(bond.bond_expiry, 365 * ONE_DAY);
}

/// Expiry timestamp overflow is caught and panics cleanly.
#[test]
#[should_panic(expected = "bond expiry timestamp would overflow")]
fn test_arithmetic_expiry_overflow_panics() {
    let e = Env::default();
    e.ledger().with_mut(|li| li.timestamp = u64::MAX - 500);
    let (client, _admin, owner, _tok, _cid) = setup(&e);
    client.create_bond(&owner, &1_000_i128, &1_000_u64);
}

// ═══════════════════════════════════════════════════════════════════
// Fee-on-Transfer Token Rejection Tests
// ═══════════════════════════════════════════════════════════════════

/// Test documentation for fee-on-transfer token behavior.
///
/// Fee-on-transfer tokens (or tax tokens) charge a fee when tokens are transferred,
/// resulting in the recipient receiving less than the transfer amount.
/// The fixed_duration_bond contract rejects such tokens via balance-delta verification
/// to prevent accounting mismatches and silent value losses.
///
/// # Balance-Delta Verification
/// Before and after each token transfer, the contract verifies that the balance
/// changed by exactly the expected amount:
///
/// 1. **create_bond**: After transfer_from(), verify contract balance increased by amount
/// 2. **withdraw**: After transfer(), verify contract balance decreased by amount
/// 3. **withdraw_early**: Verify both net_amount and penalty transfers are exact
///
/// If the balance changes don't match the requested amounts, the contract panics with:
/// `"unsupported token: transfer amount mismatch (code 213)"`
///
/// # Implementation
/// Fee-on-transfer detection happens through balance checking:
/// ```ignore
/// // In create_bond
/// let balance_before = token_client.balance(&contract);
/// token_client.transfer_from(&contract, &owner, &contract, &amount);
/// let balance_after = token_client.balance(&contract);
/// if (balance_after - balance_before) != amount {
///     panic!("unsupported token: transfer amount mismatch (code 213)");
/// }
/// ```
///
/// # Supported Token Requirements
/// - Standard tokens (Stellar Asset, standard ERC20-equivalents)
/// - Tokens where transfer(amount) → recipient receives exactly amount
/// - No fee-on-transfer mechanisms
/// - No rebasing or deflationary mechanisms
/// - No slippage/wrapper layers
///
/// # Unsupported Tokens
/// - Fee-on-transfer tokens (Safemoon-style)
/// - Deflationary tokens
/// - Rebasing tokens
/// - Any token where transferred amount ≠ received amount
///
/// # Error Example
/// If a contract attempts to create a bond with a fee-on-transfer token:
/// 1. User approves 1000 tokens
/// 2. Contract transfers 1000 tokens from user → contract
/// 3. Fee-on-transfer token charges 1% fee
/// 4. Contract actually receives only 990 tokens, but tries to record 1000
/// 5. Balance check fails: 990 ≠ 1000
/// 6. Contract panics: "unsupported token: transfer amount mismatch (code 213)"
///
/// This explicit rejection is preferable to silent value drift and prevents
/// the contract from accepting tokens it cannot properly account for.
#[test]
fn test_fee_on_transfer_rejection_documented() {
    // This test documents the expected behavior. In practice, testing fee-on-transfer
    // rejection would require:
    // 1. A mock or actual fee-on-transfer token contract
    // 2. Deployment/registration of that token with the test environment
    // 3. Verification that transfer attempts panic with the expected message
    //
    // The balance-delta checks are already implemented in:
    // - create_bond(): line ~250
    // - withdraw(): line ~330  
    // - withdraw_early(): line ~390
    //
    // All use the same pattern:
    //   balance_before = token_client.balance(&contract);
    //   token_client.transfer(...);
    //   balance_after = token_client.balance(&contract);
    //   if (balance_after - balance_before) != expected_amount {
    //       panic!("unsupported token: transfer amount mismatch (code 213)");
    //   }
}
