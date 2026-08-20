//! Hard per-operator resource accounting.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum resources available to one operator for a bounded run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub model_calls: u64,
    pub tool_calls: u64,
    pub validation_seconds: u64,
}

/// Resources charged to one operator.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceUsage {
    pub model_calls: u64,
    pub tool_calls: u64,
    pub validation_seconds: u64,
}

impl ResourceBudget {
    /// Returns the complete budget as an initially remaining allowance.
    #[must_use]
    pub const fn as_usage(self) -> ResourceUsage {
        ResourceUsage {
            model_calls: self.model_calls,
            tool_calls: self.tool_calls,
            validation_seconds: self.validation_seconds,
        }
    }
}

/// Host-owned accounting state. Agents receive remaining values but cannot
/// mutate this tracker through their home directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetTracker {
    limit: ResourceBudget,
    used: ResourceUsage,
}

impl BudgetTracker {
    #[must_use]
    pub const fn new(limit: ResourceBudget) -> Self {
        Self {
            limit,
            used: ResourceUsage {
                model_calls: 0,
                tool_calls: 0,
                validation_seconds: 0,
            },
        }
    }

    #[must_use]
    pub const fn limit(&self) -> ResourceBudget {
        self.limit
    }

    #[must_use]
    pub const fn used(&self) -> ResourceUsage {
        self.used
    }

    #[must_use]
    pub const fn remaining(&self) -> ResourceUsage {
        ResourceUsage {
            model_calls: self.limit.model_calls - self.used.model_calls,
            tool_calls: self.limit.tool_calls - self.used.tool_calls,
            validation_seconds: self.limit.validation_seconds - self.used.validation_seconds,
        }
    }

    /// Atomically charges a report. State is unchanged if any dimension would
    /// overflow or exceed its hard limit.
    pub fn charge(&mut self, charge: ResourceUsage) -> Result<(), BudgetError> {
        let model_calls = checked_dimension(
            "model_calls",
            self.used.model_calls,
            charge.model_calls,
            self.limit.model_calls,
        )?;
        let tool_calls = checked_dimension(
            "tool_calls",
            self.used.tool_calls,
            charge.tool_calls,
            self.limit.tool_calls,
        )?;
        let validation_seconds = checked_dimension(
            "validation_seconds",
            self.used.validation_seconds,
            charge.validation_seconds,
            self.limit.validation_seconds,
        )?;
        self.used = ResourceUsage {
            model_calls,
            tool_calls,
            validation_seconds,
        };
        Ok(())
    }
}

fn checked_dimension(
    dimension: &'static str,
    used: u64,
    charge: u64,
    limit: u64,
) -> Result<u64, BudgetError> {
    let requested = used
        .checked_add(charge)
        .ok_or(BudgetError::ArithmeticOverflow { dimension })?;
    if requested > limit {
        return Err(BudgetError::Exceeded {
            dimension,
            limit,
            used,
            requested: charge,
        });
    }
    Ok(requested)
}

/// Stable hard-budget rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    ArithmeticOverflow {
        dimension: &'static str,
    },
    Exceeded {
        dimension: &'static str,
        limit: u64,
        used: u64,
        requested: u64,
    },
}

impl BudgetError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ArithmeticOverflow { .. } => "OPERATOR_BUDGET_ARITHMETIC_OVERFLOW",
            Self::Exceeded { .. } => "OPERATOR_BUDGET_EXCEEDED",
        }
    }
}

impl fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow { dimension } => {
                write!(
                    formatter,
                    "operator budget arithmetic overflow for {dimension}"
                )
            }
            Self::Exceeded {
                dimension,
                limit,
                used,
                requested,
            } => write!(
                formatter,
                "operator {dimension} budget exceeded: limit {limit}, used {used}, requested {requested}"
            ),
        }
    }
}

impl std::error::Error for BudgetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_charge_is_atomic() {
        let mut tracker = BudgetTracker::new(ResourceBudget {
            model_calls: 2,
            tool_calls: 4,
            validation_seconds: 8,
        });
        tracker
            .charge(ResourceUsage {
                model_calls: 1,
                tool_calls: 2,
                validation_seconds: 3,
            })
            .unwrap();
        let prior = tracker;
        assert!(matches!(
            tracker.charge(ResourceUsage {
                model_calls: 1,
                tool_calls: 3,
                validation_seconds: 1,
            }),
            Err(BudgetError::Exceeded {
                dimension: "tool_calls",
                ..
            })
        ));
        assert_eq!(tracker, prior);
    }
}
