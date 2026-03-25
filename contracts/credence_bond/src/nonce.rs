//! Replay attack prevention using per-identity nonces and deadline enforcement.
//!
//! Each identity has a nonce that must be included in state-changing calls.
//! The contract rejects replayed transactions by requiring nonce to match
//! the stored value, then incrementing it.
//!
//! Deadline enforcement ensures signatures cannot be used after expiry,
//! preventing long-lived replay windows. Domain binding ties each operation
//! to the specific contract address, blocking cross-contract replay.

use soroban_sdk::{Address, Env};

use crate::DataKey;

/// Returns the current nonce for an identity. Caller must use this value in the next
/// state-changing call.
///
/// # Returns
/// Current nonce (starts at 0). After a successful state-changing call, the nonce increments.
#[must_use]
pub fn get_nonce(e: &Env, identity: &Address) -> u64 {
    e.storage()
        .instance()
        .get(&DataKey::Nonce(identity.clone()))
        .unwrap_or(0)
}

/// Checks that the provided nonce matches the current nonce for the identity, then increments.
/// Call this at the start of state-changing functions.
///
/// # Errors
/// Panics if `expected_nonce` does not match the stored nonce (replay or out-of-order).
pub fn consume_nonce(e: &Env, identity: &Address, expected_nonce: u64) {
    let current = get_nonce(e, identity);
    if current != expected_nonce {
        panic!("invalid nonce: replay or out-of-order");
    }
    let next = current.checked_add(1).expect("nonce overflow");
    e.storage()
        .instance()
        .set(&DataKey::Nonce(identity.clone()), &next);
}

/// Validates that the current ledger timestamp is at or before `deadline`.
///
/// This prevents signatures from being used after their intended expiry window,
/// closing the replay risk that exists when a signed payload has no time bound.
///
/// # Errors
/// Panics with "signature expired" if `block.timestamp > deadline`.
pub fn require_not_expired(e: &Env, deadline: u64) {
    let now = e.ledger().timestamp();
    if now > deadline {
        panic!("signature expired: deadline passed");
    }
}

/// Validates that the operation is bound to the current contract address.
///
/// This is the Soroban equivalent of EIP-712 domain separation: binding the
/// signed payload to a specific contract address prevents cross-contract replay
/// where a valid signature for contract A is submitted to contract B.
///
/// # Errors
/// Panics with "domain mismatch" if `expected_contract` does not match the
/// current contract address.
pub fn require_domain_match(e: &Env, expected_contract: &Address) {
    let current = e.current_contract_address();
    if current != *expected_contract {
        panic!("domain mismatch: wrong contract address");
    }
}

/// Convenience: validate deadline + domain + consume nonce in one call.
///
/// This is the canonical entry point for permit-like flows. Call this before
/// any state mutation in functions that accept off-chain-signed authorization.
///
/// Order of checks:
/// 1. Deadline — fail fast on expired signatures before touching storage.
/// 2. Domain   — ensure the payload was signed for this contract.
/// 3. Nonce    — prevent replay and enforce ordering.
pub fn validate_and_consume(
    e: &Env,
    identity: &Address,
    expected_contract: &Address,
    deadline: u64,
    nonce: u64,
) {
    require_not_expired(e, deadline);
    require_domain_match(e, expected_contract);
    consume_nonce(e, identity, nonce);
}
