//! Checked integer arithmetic and explicit consensus rounding rules.

use core::fmt;

/// A failure from a checked consensus arithmetic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticError {
    /// The mathematically correct result is outside the destination integer type.
    Overflow,
    /// Division or remainder by zero was requested.
    DivisionByZero,
}

impl fmt::Display for ArithmeticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => formatter.write_str("integer arithmetic overflow"),
            Self::DivisionByZero => formatter.write_str("integer division by zero"),
        }
    }
}

impl std::error::Error for ArithmeticError {}

/// Fixed-width integer operations used by the checked helper functions.
///
/// This trait is sealed to the architecture-independent integer primitives.
pub trait CheckedInteger: private::Sealed + Copy {
    #[doc(hidden)]
    fn checked_add_inner(self, right: Self) -> Option<Self>;
    #[doc(hidden)]
    fn checked_sub_inner(self, right: Self) -> Option<Self>;
    #[doc(hidden)]
    fn checked_mul_inner(self, right: Self) -> Option<Self>;
    #[doc(hidden)]
    fn checked_div_inner(self, right: Self) -> Option<Self>;
    #[doc(hidden)]
    fn checked_rem_inner(self, right: Self) -> Option<Self>;
    #[doc(hidden)]
    fn is_zero(self) -> bool;
}

mod private {
    pub trait Sealed {}
}

macro_rules! checked_integer {
    ($($integer:ty),+ $(,)?) => {
        $(
            impl private::Sealed for $integer {}

            impl CheckedInteger for $integer {
                fn checked_add_inner(self, right: Self) -> Option<Self> {
                    self.checked_add(right)
                }

                fn checked_sub_inner(self, right: Self) -> Option<Self> {
                    self.checked_sub(right)
                }

                fn checked_mul_inner(self, right: Self) -> Option<Self> {
                    self.checked_mul(right)
                }

                fn checked_div_inner(self, right: Self) -> Option<Self> {
                    self.checked_div(right)
                }

                fn checked_rem_inner(self, right: Self) -> Option<Self> {
                    self.checked_rem(right)
                }

                fn is_zero(self) -> bool {
                    self == 0
                }
            }
        )+
    };
}

checked_integer!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// Adds two fixed-width integers, returning an error on overflow.
pub fn checked_add<T: CheckedInteger>(left: T, right: T) -> Result<T, ArithmeticError> {
    left.checked_add_inner(right)
        .ok_or(ArithmeticError::Overflow)
}

/// Subtracts two fixed-width integers, returning an error on overflow.
pub fn checked_sub<T: CheckedInteger>(left: T, right: T) -> Result<T, ArithmeticError> {
    left.checked_sub_inner(right)
        .ok_or(ArithmeticError::Overflow)
}

/// Multiplies two fixed-width integers, returning an error on overflow.
pub fn checked_mul<T: CheckedInteger>(left: T, right: T) -> Result<T, ArithmeticError> {
    left.checked_mul_inner(right)
        .ok_or(ArithmeticError::Overflow)
}

/// Divides two fixed-width integers with truncation toward zero.
pub fn checked_div<T: CheckedInteger>(left: T, right: T) -> Result<T, ArithmeticError> {
    if right.is_zero() {
        return Err(ArithmeticError::DivisionByZero);
    }
    left.checked_div_inner(right)
        .ok_or(ArithmeticError::Overflow)
}

/// Computes an integer remainder, rejecting a zero divisor and signed overflow.
pub fn checked_rem<T: CheckedInteger>(left: T, right: T) -> Result<T, ArithmeticError> {
    if right.is_zero() {
        return Err(ArithmeticError::DivisionByZero);
    }
    left.checked_rem_inner(right)
        .ok_or(ArithmeticError::Overflow)
}

/// A rounding rule that must be selected explicitly for non-exact division.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RoundingMode {
    /// Round toward zero.
    TowardZero = 0,
    /// Round away from zero.
    AwayFromZero = 1,
    /// Round toward negative infinity.
    Floor = 2,
    /// Round toward positive infinity.
    Ceiling = 3,
    /// Round to the nearest integer; exact halves choose the even integer.
    NearestTiesToEven = 4,
}

/// Divides unsigned scaled values according to a declared rounding rule.
pub fn checked_div_round_u128(
    numerator: u128,
    denominator: u128,
    mode: RoundingMode,
) -> Result<u128, ArithmeticError> {
    if denominator == 0 {
        return Err(ArithmeticError::DivisionByZero);
    }

    let quotient = numerator / denominator;
    let remainder = numerator % denominator;
    if remainder == 0 {
        return Ok(quotient);
    }

    let round_up = match mode {
        RoundingMode::TowardZero | RoundingMode::Floor => false,
        RoundingMode::AwayFromZero | RoundingMode::Ceiling => true,
        RoundingMode::NearestTiesToEven => {
            let distance_to_next = denominator - remainder;
            remainder > distance_to_next
                || (remainder == distance_to_next && !quotient.is_multiple_of(2))
        }
    };

    if round_up {
        quotient.checked_add(1).ok_or(ArithmeticError::Overflow)
    } else {
        Ok(quotient)
    }
}

/// Divides signed scaled values according to a declared rounding rule.
pub fn checked_div_round_i128(
    numerator: i128,
    denominator: i128,
    mode: RoundingMode,
) -> Result<i128, ArithmeticError> {
    let quotient = checked_div(numerator, denominator)?;
    let remainder = checked_rem(numerator, denominator)?;
    if remainder == 0 {
        return Ok(quotient);
    }

    let positive_result = (numerator < 0) == (denominator < 0);
    let away_from_zero = || {
        if positive_result {
            quotient.checked_add(1).ok_or(ArithmeticError::Overflow)
        } else {
            quotient.checked_sub(1).ok_or(ArithmeticError::Overflow)
        }
    };

    match mode {
        RoundingMode::TowardZero => Ok(quotient),
        RoundingMode::AwayFromZero => away_from_zero(),
        RoundingMode::Floor if !positive_result => {
            quotient.checked_sub(1).ok_or(ArithmeticError::Overflow)
        }
        RoundingMode::Ceiling if positive_result => {
            quotient.checked_add(1).ok_or(ArithmeticError::Overflow)
        }
        RoundingMode::Floor | RoundingMode::Ceiling => Ok(quotient),
        RoundingMode::NearestTiesToEven => {
            let doubled_remainder = remainder
                .unsigned_abs()
                .checked_mul(2)
                .ok_or(ArithmeticError::Overflow)?;
            let denominator_magnitude = denominator.unsigned_abs();
            if doubled_remainder > denominator_magnitude
                || (doubled_remainder == denominator_magnitude
                    && !quotient.unsigned_abs().is_multiple_of(2))
            {
                away_from_zero()
            } else {
                Ok(quotient)
            }
        }
    }
}

/// Multiplies then divides unsigned scaled values with checked intermediates.
pub fn checked_mul_div_u128(
    left: u128,
    right: u128,
    denominator: u128,
    mode: RoundingMode,
) -> Result<u128, ArithmeticError> {
    checked_div_round_u128(checked_mul(left, right)?, denominator, mode)
}

/// Multiplies then divides signed scaled values with checked intermediates.
pub fn checked_mul_div_i128(
    left: i128,
    right: i128,
    denominator: i128,
    mode: RoundingMode,
) -> Result<i128, ArithmeticError> {
    checked_div_round_i128(checked_mul(left, right)?, denominator, mode)
}

/// The inclusive range of basis points is `0..=10_000`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct BasisPoints(u16);

impl BasisPoints {
    /// One hundred percent in basis points.
    pub const FULL: Self = Self(10_000);
    /// Zero percent in basis points.
    pub const ZERO: Self = Self(0);

    /// Validates and constructs a basis-point value.
    pub const fn new(value: u16) -> Result<Self, BasisPointsError> {
        if value <= Self::FULL.0 {
            Ok(Self(value))
        } else {
            Err(BasisPointsError { value })
        }
    }

    /// Returns the integer number of basis points.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Applies this rate to an unsigned amount with a declared rounding rule.
    pub fn apply_u64(self, amount: u64, mode: RoundingMode) -> Result<u64, ArithmeticError> {
        let result = checked_mul_div_u128(
            u128::from(amount),
            u128::from(self.0),
            u128::from(Self::FULL.0),
            mode,
        )?;
        u64::try_from(result).map_err(|_| ArithmeticError::Overflow)
    }
}

impl TryFrom<u16> for BasisPoints {
    type Error = BasisPointsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<BasisPoints> for u16 {
    fn from(value: BasisPoints) -> Self {
        value.get()
    }
}

/// A basis-point value exceeded 100 percent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BasisPointsError {
    value: u16,
}

impl BasisPointsError {
    /// Returns the rejected integer value.
    pub const fn value(self) -> u16 {
        self.value
    }
}

impl fmt::Display for BasisPointsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "basis points {} exceed 10000", self.value)
    }
}

impl std::error::Error for BasisPointsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_arithmetic_reports_every_boundary() {
        assert_eq!(checked_add(u64::MAX, 1), Err(ArithmeticError::Overflow));
        assert_eq!(checked_sub(0_u64, 1), Err(ArithmeticError::Overflow));
        assert_eq!(checked_mul(u128::MAX, 2), Err(ArithmeticError::Overflow));
        assert_eq!(checked_div(1_u64, 0), Err(ArithmeticError::DivisionByZero));
        assert_eq!(checked_rem(1_i64, 0), Err(ArithmeticError::DivisionByZero));
        assert_eq!(checked_div(i64::MIN, -1), Err(ArithmeticError::Overflow));
        assert_eq!(checked_rem(i64::MIN, -1), Err(ArithmeticError::Overflow));
        assert_eq!(checked_add(20_u32, 22), Ok(42));
    }

    #[test]
    fn unsigned_rounding_rules_are_declared() {
        assert_eq!(
            checked_div_round_u128(5, 2, RoundingMode::TowardZero),
            Ok(2)
        );
        assert_eq!(checked_div_round_u128(5, 2, RoundingMode::Floor), Ok(2));
        assert_eq!(
            checked_div_round_u128(5, 2, RoundingMode::AwayFromZero),
            Ok(3)
        );
        assert_eq!(checked_div_round_u128(5, 2, RoundingMode::Ceiling), Ok(3));
        assert_eq!(
            checked_div_round_u128(5, 2, RoundingMode::NearestTiesToEven),
            Ok(2)
        );
        assert_eq!(
            checked_div_round_u128(7, 2, RoundingMode::NearestTiesToEven),
            Ok(4)
        );
        assert_eq!(
            checked_div_round_u128(u128::MAX - 1, u128::MAX, RoundingMode::NearestTiesToEven),
            Ok(1)
        );
    }

    #[test]
    fn signed_rounding_rules_handle_both_signs() {
        assert_eq!(
            checked_div_round_i128(-5, 2, RoundingMode::TowardZero),
            Ok(-2)
        );
        assert_eq!(checked_div_round_i128(-5, 2, RoundingMode::Floor), Ok(-3));
        assert_eq!(checked_div_round_i128(-5, 2, RoundingMode::Ceiling), Ok(-2));
        assert_eq!(
            checked_div_round_i128(-5, 2, RoundingMode::AwayFromZero),
            Ok(-3)
        );
        assert_eq!(
            checked_div_round_i128(-5, 2, RoundingMode::NearestTiesToEven),
            Ok(-2)
        );
        assert_eq!(
            checked_div_round_i128(-7, 2, RoundingMode::NearestTiesToEven),
            Ok(-4)
        );
        assert_eq!(checked_div_round_i128(1, -2, RoundingMode::Floor), Ok(-1));
        assert_eq!(checked_div_round_i128(1, -2, RoundingMode::Ceiling), Ok(0));
    }

    #[test]
    fn exact_division_ignores_rounding_mode() {
        for mode in [
            RoundingMode::TowardZero,
            RoundingMode::AwayFromZero,
            RoundingMode::Floor,
            RoundingMode::Ceiling,
            RoundingMode::NearestTiesToEven,
        ] {
            assert_eq!(checked_div_round_u128(6, 3, mode), Ok(2));
            assert_eq!(checked_div_round_i128(-6, 3, mode), Ok(-2));
        }
    }

    #[test]
    fn scaled_multiplication_and_basis_points_are_checked() {
        assert_eq!(checked_mul_div_u128(3, 5, 2, RoundingMode::Ceiling), Ok(8));
        assert_eq!(
            checked_mul_div_u128(u128::MAX, 2, 1, RoundingMode::Floor),
            Err(ArithmeticError::Overflow)
        );

        let one_third = BasisPoints::new(3_333).expect("valid basis points");
        assert_eq!(one_third.apply_u64(3, RoundingMode::Floor), Ok(0));
        assert_eq!(one_third.apply_u64(3, RoundingMode::Ceiling), Ok(1));
        assert_eq!(
            BasisPoints::FULL.apply_u64(u64::MAX, RoundingMode::Floor),
            Ok(u64::MAX)
        );
        assert_eq!(
            BasisPoints::new(10_001),
            Err(BasisPointsError { value: 10_001 })
        );
    }
}
