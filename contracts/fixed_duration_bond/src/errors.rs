/// All panic messages used by the fixed_duration_bond contract.
///
/// Using string constants avoids typos in `#[should_panic(expected = "...")]` tests.
pub const ERR_ALREADY_INITIALIZED: &str = "already initialized";
pub const ERR_NOT_INITIALIZED: &str = "not initialized";
pub const ERR_UNAUTHORIZED: &str = "unauthorized";
pub const ERR_INVALID_AMOUNT: &str = "amount must be positive";
pub const ERR_INVALID_DURATION: &str = "duration must be positive";
pub const ERR_DURATION_OVERFLOW: &str = "bond expiry timestamp would overflow";
pub const ERR_BOND_ACTIVE: &str = "bond already active for this owner";
pub const ERR_NO_BOND: &str = "no active bond found";
pub const ERR_LOCK_PERIOD_NOT_ELAPSED: &str = "lock period has not elapsed yet";
#[allow(dead_code)]
pub const ERR_INSUFFICIENT_BALANCE: &str = "insufficient bond balance";
pub const ERR_TOKEN_NOT_SET: &str = "token not set";
pub const ERR_NO_FEES: &str = "no fees to collect";
pub const ERR_PENALTY_NOT_CONFIGURED: &str = "early-exit penalty not configured";
pub const ERR_FEE_BPS_TOO_HIGH: &str = "fee_bps must be <= 1000 (10%)";
pub const ERR_FEE_MUL_OVERFLOW: &str = "fee calculation overflow";
pub const ERR_FEE_ACCRUE_OVERFLOW: &str = "accrued fees overflow";
pub const ERR_ORACLE_BOUNDS_INVALID: &str = "oracle bounds invalid";
pub const ERR_ORACLE_SAFETY_NOT_SET: &str = "oracle safety not configured for asset";
pub const ERR_ORACLE_ANSWER_NON_POSITIVE: &str = "oracle answer must be positive";
pub const ERR_ORACLE_ANSWER_OUT_OF_RANGE: &str = "oracle answer out of configured range";
pub const ERR_VALUATION_OVERFLOW: &str = "valuation overflow";
