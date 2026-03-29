#![no_std]

/// Fixed-point denominator for basis-point calculations.
pub const BPS_DENOMINATOR: i128 = 10_000;

/// Checked `u64` multiplication with a stable panic message.
#[inline]
#[must_use]
pub fn mul_u64(a: u64, b: u64, msg: &'static str) -> u64 {
    a.checked_mul(b).unwrap_or_else(|| panic!("{msg}"))
}

/// Checked `i128` addition with a stable panic message.
#[inline]
#[must_use]
pub fn add_i128(a: i128, b: i128, msg: &'static str) -> i128 {
    a.checked_add(b).unwrap_or_else(|| panic!("{msg}"))
}

/// Checked `i128` subtraction with a stable panic message.
#[inline]
#[must_use]
pub fn sub_i128(a: i128, b: i128, msg: &'static str) -> i128 {
    a.checked_sub(b).unwrap_or_else(|| panic!("{msg}"))
}

/// Checked `i128` multiplication with a stable panic message.
#[inline]
#[must_use]
pub fn mul_i128(a: i128, b: i128, msg: &'static str) -> i128 {
    a.checked_mul(b).unwrap_or_else(|| panic!("{msg}"))
}

/// Checked `i128` division with a stable panic message.
#[inline]
#[must_use]
pub fn div_i128(a: i128, b: i128, msg: &'static str) -> i128 {
    a.checked_div(b).unwrap_or_else(|| panic!("{msg}"))
}

/// Calculate a basis-point percentage of an `i128` amount: `amount * bps / 10_000`.
#[inline]
#[must_use]
pub fn bps(amount: i128, bps: u32, mul_msg: &'static str, div_msg: &'static str) -> i128 {
    let numerator = mul_i128(amount, bps as i128, mul_msg);
    div_i128(numerator, BPS_DENOMINATOR, div_msg)
}

/// Calculate a basis-point percentage of a `u64` amount: `amount * bps / 10_000`.
#[inline]
#[must_use]
pub fn bps_u64(amount: u64, bps: u32, mul_msg: &'static str) -> u64 {
    mul_u64(amount, bps as u64, mul_msg) / BPS_DENOMINATOR as u64
}

/// Split an amount into `(fee, net)` using basis-point math.
#[inline]
#[must_use]
pub fn split_bps(
    amount: i128,
    bps_value: u32,
    mul_msg: &'static str,
    div_msg: &'static str,
    sub_msg: &'static str,
) -> (i128, i128) {
    let fee = bps(amount, bps_value, mul_msg, div_msg);
    let net = sub_i128(amount, fee, sub_msg);
    (fee, net)
}

#[cfg(test)]
mod tests {
    use super::{bps, bps_u64, split_bps};

    fn legacy_bps_i128(amount: i128, bps: u32) -> i128 {
        amount
            .checked_mul(bps as i128)
            .expect("legacy i128 overflow")
            / 10_000
    }

    fn legacy_bps_u64(amount: u64, bps: u32) -> u64 {
        amount.checked_mul(bps as u64).expect("legacy u64 overflow") / 10_000
    }

    fn legacy_split_bps(amount: i128, bps: u32) -> (i128, i128) {
        let fee = legacy_bps_i128(amount, bps);
        let net = amount.checked_sub(fee).expect("legacy i128 underflow");
        (fee, net)
    }

    #[test]
    fn bps_matches_legacy_formula() {
        let cases = [
            (0_i128, 0_u32),
            (1, 1),
            (10_000, 100),
            (999_999, 333),
            (1_000_000_000, 50),
            (i128::MAX / 20_000, 10_000),
        ];

        for (amount, bps_value) in cases {
            assert_eq!(
                bps(amount, bps_value, "mul", "div"),
                legacy_bps_i128(amount, bps_value)
            );
        }
    }

    #[test]
    fn bps_u64_matches_legacy_formula() {
        let cases = [
            (0_u64, 0_u32),
            (1, 1),
            (10_000, 100),
            (999_999, 333),
            (u64::MAX / 20_000, 10_000),
        ];

        for (amount, bps_value) in cases {
            assert_eq!(
                bps_u64(amount, bps_value, "mul"),
                legacy_bps_u64(amount, bps_value)
            );
        }
    }

    #[test]
    fn split_bps_matches_legacy_formula() {
        let cases = [
            (0_i128, 0_u32),
            (10_000, 100),
            (10_000, 1_000),
            (123_456_789, 75),
            (i128::MAX / 20_000, 10_000),
        ];

        for (amount, bps_value) in cases {
            assert_eq!(
                split_bps(amount, bps_value, "mul", "div", "sub"),
                legacy_split_bps(amount, bps_value)
            );
        }
    }
}
