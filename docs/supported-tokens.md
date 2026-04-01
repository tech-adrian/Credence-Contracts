# Supported Token Behavior

**Last Updated**: 2026-03-29
**Issue Reference**: #142 - Reject fee-on-transfer tokens where unsupported
**Status**: Implemented & Documented

## Overview

The Credence Protocol contracts explicitly reject tokens where the transfer amount does not equal the balance change. This document specifies which tokens are supported and why this restriction exists.

## Supported Tokens

✅ **Fully Supported:**
- **Stellar Asset Contracts** - Standard Stellar native assets and issued assets
- **Standard ERC20-Equivalent Tokens** - Tokens following the base token interface with no additional fees
  - Transfer of amount X results in recipient receiving exactly X
  - No deflation, rebasing, or fees on transfer
- **USDC, USDT, and similar stablecoin reference implementations** - When deployed following standard patterns

### Token Requirements

For a token to be supported by Credence contracts, it must satisfy these conditions:

```rust
// For every transfer call:
let balance_before_recipient = token.balanceOf(recipient);
token.transfer(recipient, amount);
let balance_after_recipient = token.balanceOf(recipient);

// This must be true:
assert_eq!(balance_after_recipient - balance_before_recipient, amount);
```

In other words:
- **What you send is what the recipient receives**
- No fees, taxes, or cuts applied by the token contract
- No rebasing or dynamic supply adjustments during transfer
- No hidden locks or vesting periods

## Unsupported Tokens

❌ **Explicitly Rejected:**
- **Fee-on-Transfer Tokens** - Tokens that charge a fee on every transfer
  - Example: Safemoon-style tokens with built-in marketing/liquidity fees
  - Sending 1000 tokens might only deliver 990 (1% fee)
- **Deflationary Tokens** - Tokens with built-in burning mechanisms
- **Rebasing Tokens** - Tokens where all balances automatically adjust
  - Example: Ampleforth-style tokens
- **Wrapper / Bridge Tokens with Slippage** - Tokens that lose value in wrapping/unwrapping
- **Tokens with Variable Decimals** - Tokens where decimals can change
- **Any Token with Transfer Hooks** - Tokens with callbacks on transfer that modify amounts

## Why This Restriction Exists

### The Problem

The Credence Protocol contracts assume transfer integrity: when the contract transfers X tokens, it expects those X tokens to be received. With fee-on-transfer tokens:

```
User Scenario:
1. Bond contract transfers 1000 tokens FROM user INTO bond contract
2. Fee-on-transfer token takes 10 tokens (1% fee) 
3. Bond contract receives only 990 tokens
4. Bond records 1000 tokens bonded (MISMATCH!)
5. Later:
   - Bond tries to withdraw 1000 tokens
   - Only 990 available → FAILURE
   - Funds are lost or locked
```

### The Solution

All contracts now verify balance changes via balance-delta checking:

```rust
// Example from credence_bond/src/token_integration.rs
let balance_before = token_client.balance(&contract);
token_client.transfer_from(&contract, owner, &contract, &amount);
let balance_after = token_client.balance(&contract);
let actual_received = balance_after - balance_before;

if actual_received != amount {
    panic!("unsupported token: transfer amount mismatch (code 213)");
}
```

This approach:
- ✅ Detects fee-on-transfer tokens immediately
- ✅ Prevents silent value drift
- ✅ Rejects the operation rather than corrupting state
- ✅ Provides explicit error code (213) for debugging

## Error Codes

### Error 213: UnsupportedToken

**Message**: `"unsupported token: transfer amount mismatch (code 213)"`

**Triggered When**: 
- A token transfer completes, but the balance change doesn't match the requested amount
- This indicates a fee-on-transfer or similar mechanism

**Contracts Affected**:
- credence_bond (all transfers)
- dispute_resolution (stake transfers)
- fixed_duration_bond (all transfers)

**Error Type**: `ContractError::UnsupportedToken` (from credence_errors)

**Example Scenarios**:

1. **Bond Creation Rejection**
   ```
   User attempts: create_bond(amount=1000)
   Token charged 10-token fee internally
   Error: UnsupportedToken on transfer_into_contract
   Result: Bond not created, no state change
   ```

2. **Dispute Creation Rejection**
   ```
   Disputer attempts: create_dispute(stake=500)
   Fee-on-transfer token charges 2% on transfer
   Error: TransferFailed (code 9) on create_dispute
   Result: Dispute not created, no tokens transferred
   ```

3. **Bond Withdrawal Rejection**
   ```
   User attempts: withdraw(amount=1000)
   Token charges fee on outgoing transfer
   Error: UnsupportedToken on transfer_from_contract
   Result: Withdrawal fails, bond frozen with panic
   ```

## Contract-by-Contract Implementation

### credence_bond

**Files**: `src/token_integration.rs`

**Functions Protected**:
- `transfer_into_contract()` - Verifies amount received on bond creation
- `transfer_from_contract()` - Verifies amount sent on withdrawal/penalties

**Balance Check Pattern**:
```rust
pub fn transfer_into_contract(e: &Env, owner: &Address, amount: i128) {
    // ... validation ...
    let balance_before = token_client(e).balance(&contract);
    token_client(e).transfer_from(&contract, owner, &contract, &amount);
    let balance_after = token_client(e).balance(&contract);
    
    if (balance_after - balance_before) != amount {
        panic!("unsupported token: transfer amount mismatch (code 213)");
    }
}
```

**Affected Operations**:
- `create_bond()` - Rejects on transfer_in
- `create_bond_with_rolling()` - Rejects on transfer_in
- `withdraw_bond()` - Rejects on transfer_out
- `withdraw_early()` - Rejects on transfer_out
- Early exit penalties - Rejects on transfer to treasury

### dispute_resolution

**Files**: `src/lib.rs`

**Functions Protected**:
- `create_dispute()` - Verifies stake received (code 9: TransferFailed)
- `resolve_dispute()` - Verifies stake returned, if dispute favors disputer (code 9: TransferFailed)

**Balance Check Pattern**:
```rust
pub fn create_dispute(...) -> Result<u64, Error> {
    // ... validation ...
    let balance_before = token_client.balance(&contract_address);
    token_client.transfer_from(&contract_address, &disputer, &contract_address, &stake);
    let balance_after = token_client.balance(&contract_address);
    
    if (balance_after - balance_before) != stake {
        return Err(Error::TransferFailed);  // Code 9
    }
    // ... continue dispute creation ...
    Ok(dispute_id)
}
```

### fixed_duration_bond

**Files**: `src/lib.rs`

**Functions Protected**:
- `create_bond()` - Verifies correct amount received on creation
- `withdraw()` - Verifies correct amount sent at maturity
- `withdraw_early()` - Verifies both net amount and penalty transfers

**Balance Check Pattern**:
```rust
let balance_before = token_client.balance(&contract);
token_client.transfer(...);
let balance_after = token_client.balance(&contract);

if (balance_before - balance_after) != expected_amount {
    panic!("{}", ERR_UNSUPPORTED_TOKEN);  // Code 213
}
```

### credence_treasury

**Design Note**: Treasury does NOT hold tokens directly. It is a pure accounting system.
- `receive_fee()` - Accepts fee reports from bond contracts (no token transfer)
- `execute_withdrawal()` - Updates internal balance tracking (no token transfer)

Fee-on-transfer token rejection happens at the bond level, where fees originate.

## Migration Guide for Users

If you're using a token that is blocked (error 213 or 9):

### Option 1: Switch to a Supported Token ⭐ **Recommended**
1. Identify a supported stablecoin or standard token (USDC, USDT, Stellar USD, etc.)
2. If using a wrapped token, unwrap to the canonical version
3. Restart your bond with the supported token

### Option 2: Custom Token Wrapper
If you must use an unsupported token, create a wrapper contract that:
1. Accepts unsupported token transfers with fees
2. Performs the bond operations using the fee-accounted amount
3. Handles unwinding when the bond matures

**Example wrapper logic**:
```rust
// In wrapper contract:
fn bond_with_fee_token(amount: i128) -> i128 {
    // Transfer from user
    fee_token.transfer_from(user, wrapper, amount);
    
    // Record actual received amount (after fees)
    let actual_amount = amount - estimated_fees;
    
    // Pass to bond contract (now safe)
    bond_client.create_bond(actual_amount);
    
    actual_amount
}
```

### Option 3: Governance Proposal
If a supported token should be added to the network, governance can:
1. Audit the token contract for fee-on-transfer mechanisms
2. Propose it as a supported asset
3. Update documentation

## Testing

### How to Test Token Support

When integrating a new token:

```bash
# Compile and run bond tests with your token contract:
cargo test test_create_bond_success

# If balance-delta checks work, you'll see:
# test test_create_bond_success ... ok

# If your token has fees, you'll see:
# thread panicked at 'unsupported token: transfer amount mismatch (code 213)'
```

### Test Files

- **credence_bond**: `tests/test_fee_on_transfer_rejection.rs`
- **fixed_duration_bond**: `src/tests.rs` (search "fee_on_transfer")
- **dispute_resolution**: `src/test.rs` (search "fee_on_transfer")

## FAQ

**Q: Will my bonds work with USDC?**  
A: Yes. USDC is a standard token with no fees. It's fully supported.

**Q: What about wrapped tokens (e.g., wrapped Bitcoin)?**  
A: Wrapped tokens are supported IF the wrapper itself has no fees. Most canonical wrapped tokens (like Wrapped Ethereum) are supported.

**Q: Can I use a stablecoin with small redemption fees?**  
A: No. Any mechanism where transfer(X) ≠ receive(X) is unsupported and will be rejected.

**Q: Why not just trust the token and adjust for fees?**  
A: Because:
1. It's error-prone - we'd need to know each token's fee rate
2. It's unsafe - different tokens have different fee structures
3. It's explicit - rejecting is better than silently losing value
4. It's clear to users - they get an immediate error

**Q: Is this a limitation of Soroban or Credence?**  
A: It's a design choice by Credence for safety. Soroban's token interface is standard and adequate; the limitation is in our contracts' assumptions about tokens.

**Q: Can I disable these checks?**  
A: No. These checks are core safety mechanisms, not configuration options. They prevent funds from being lost or locked.

**Q: What if I accidentally use a fee-on-transfer token?**  
A: The contract will panic with error 213 before any bond is created. Your tokens won't be locked and no state will change. Switch to a supported token and try again.

## Summary Table

| Token Type | Supported | Error | Action |
|-----------|-----------|-------|--------|
| Standard ERC20 / Stellar Asset | ✅ Yes | - | Works normally |
| USDC, USDT (canonical) | ✅ Yes | - | Works normally |
| Fee-on-transfer | ❌ No | 213 | Rejected at transfer |
| Deflationary | ❌ No | 213 | Rejected at transfer |
| Rebasing | ❌ No | 213 | Rejected at transfer |
| Wrapped with slippage | ❌ No | 213 | Rejected at transfer |

## References

- [Issue #142](https://github.com/credenceprotocol/credence-contracts/issues/142) - Reject fee-on-transfer tokens
- [Error Code 213](docs/error-codes.md) - UnsupportedToken
- [Token Integration](contracts/credence_bond/src/token_integration.rs) - Implementation
- [Balance Delta Checks](contracts/fixed_duration_bond/src/lib.rs) - Pattern example

## Contact & Support

For questions about token support:
1. Check this document
2. Review error codes in [credence_errors/src/lib.rs](contracts/credence_errors/src/lib.rs)
3. Open an issue with your token contract address for audit
