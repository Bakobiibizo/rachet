//! Reconciled section 36 resource accounting.

use std::{collections::BTreeMap, error::Error, fmt};

use serde::{Deserialize, Serialize};

const RESOURCE_SCHEMA_VERSION: u32 = 1;

/// Raw resource use attributable to one operator operation in one epoch.
///
/// Optional counters distinguish an observed zero (`Some(0)`) from a host that
/// could not provide the counter (`None`). Durations use monotonic elapsed time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRecord {
    pub operator: String,
    pub epoch: u64,
    pub model_calls: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub tool_calls: u64,
    pub command_duration_ms: u64,
    pub cpu_time_ms: Option<u64>,
    pub validation_wall_clock_allowance_ms: u64,
    pub git_objects_read: u64,
    pub files_inspected: u64,
    pub tests_executed: u64,
    pub jobs_inspected: u64,
    pub jobs_accepted: u64,
    pub claims_evaluated: u64,
    pub evidence_bytes: u64,
    /// Preregistered, implementation-independent compute units, when defined.
    pub compute_units: Option<u64>,
}

/// A reconciled optional counter.
///
/// `Partial` retains the sum of all observed values and the exact number of raw
/// records for which the host could not provide a value. It must not be treated
/// as a complete total.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "availability", rename_all = "snake_case", deny_unknown_fields)]
pub enum AvailabilityTotal {
    Complete {
        total: u64,
    },
    Partial {
        known_total: u64,
        unavailable_records: u64,
    },
}

impl AvailabilityTotal {
    #[must_use]
    pub const fn complete_value(self) -> Option<u64> {
        match self {
            Self::Complete { total } => Some(total),
            Self::Partial { .. } => None,
        }
    }
}

/// Exact totals derived from all retained raw records.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceTotals {
    pub records: u64,
    pub model_calls: u64,
    pub input_tokens: AvailabilityTotal,
    pub output_tokens: AvailabilityTotal,
    pub tool_calls: u64,
    pub command_duration_ms: u64,
    pub cpu_time_ms: AvailabilityTotal,
    pub validation_wall_clock_allowance_ms: u64,
    pub git_objects_read: u64,
    pub files_inspected: u64,
    pub tests_executed: u64,
    pub jobs_inspected: u64,
    pub jobs_accepted: u64,
    pub claims_evaluated: u64,
    pub evidence_bytes: u64,
    pub compute_units: AvailabilityTotal,
}

/// Reconciled resource use for one validation operator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorResourceTotals {
    pub operator: String,
    pub totals: ResourceTotals,
}

/// A self-reconciling `resources.json` document containing raw records and totals.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAccounting {
    pub schema_version: u32,
    pub records: Vec<ResourceRecord>,
    pub totals: ResourceTotals,
    pub by_operator: Vec<OperatorResourceTotals>,
}

impl ResourceAccounting {
    /// Validates raw records and computes every total with checked arithmetic.
    pub fn from_records(records: Vec<ResourceRecord>) -> Result<Self, ResourceAccountingError> {
        for record in &records {
            validate_identifier("resource operator", &record.operator)?;
        }
        let totals = ResourceTotals::reconcile(&records)?;
        let by_operator = reconcile_by_operator(&records)?;
        Ok(Self {
            schema_version: RESOURCE_SCHEMA_VERSION,
            records,
            totals,
            by_operator,
        })
    }

    /// Recomputes totals and rejects a decoded or externally assembled mismatch.
    pub fn verify(&self) -> Result<(), ResourceAccountingError> {
        if self.schema_version != RESOURCE_SCHEMA_VERSION {
            return Err(ResourceAccountingError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        for record in &self.records {
            validate_identifier("resource operator", &record.operator)?;
        }
        let reconciled = ResourceTotals::reconcile(&self.records)?;
        let by_operator = reconcile_by_operator(&self.records)?;
        if reconciled != self.totals || by_operator != self.by_operator {
            return Err(ResourceAccountingError::TotalsMismatch);
        }
        Ok(())
    }

    /// Encodes a stable pretty-printed artifact with one trailing newline.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

fn reconcile_by_operator(
    records: &[ResourceRecord],
) -> Result<Vec<OperatorResourceTotals>, ResourceAccountingError> {
    let mut grouped: BTreeMap<String, Vec<ResourceRecord>> = BTreeMap::new();
    for record in records {
        grouped
            .entry(record.operator.clone())
            .or_default()
            .push(record.clone());
    }
    grouped
        .into_iter()
        .map(|(operator, records)| {
            Ok(OperatorResourceTotals {
                operator,
                totals: ResourceTotals::reconcile(&records)?,
            })
        })
        .collect()
}

impl ResourceTotals {
    fn reconcile(records: &[ResourceRecord]) -> Result<Self, ResourceAccountingError> {
        let mut totals = Self {
            records: 0,
            model_calls: 0,
            input_tokens: AvailabilityTotal::Complete { total: 0 },
            output_tokens: AvailabilityTotal::Complete { total: 0 },
            tool_calls: 0,
            command_duration_ms: 0,
            cpu_time_ms: AvailabilityTotal::Complete { total: 0 },
            validation_wall_clock_allowance_ms: 0,
            git_objects_read: 0,
            files_inspected: 0,
            tests_executed: 0,
            jobs_inspected: 0,
            jobs_accepted: 0,
            claims_evaluated: 0,
            evidence_bytes: 0,
            compute_units: AvailabilityTotal::Complete { total: 0 },
        };
        let mut input_tokens = OptionalAccumulator::default();
        let mut output_tokens = OptionalAccumulator::default();
        let mut cpu_time_ms = OptionalAccumulator::default();
        let mut compute_units = OptionalAccumulator::default();

        for record in records {
            add(&mut totals.records, 1, "records")?;
            add(&mut totals.model_calls, record.model_calls, "model calls")?;
            input_tokens.add(record.input_tokens, "input tokens")?;
            output_tokens.add(record.output_tokens, "output tokens")?;
            add(&mut totals.tool_calls, record.tool_calls, "tool calls")?;
            add(
                &mut totals.command_duration_ms,
                record.command_duration_ms,
                "command duration",
            )?;
            cpu_time_ms.add(record.cpu_time_ms, "CPU time")?;
            add(
                &mut totals.validation_wall_clock_allowance_ms,
                record.validation_wall_clock_allowance_ms,
                "validation wall-clock allowance",
            )?;
            add(
                &mut totals.git_objects_read,
                record.git_objects_read,
                "Git objects read",
            )?;
            add(
                &mut totals.files_inspected,
                record.files_inspected,
                "files inspected",
            )?;
            add(
                &mut totals.tests_executed,
                record.tests_executed,
                "tests executed",
            )?;
            add(
                &mut totals.jobs_inspected,
                record.jobs_inspected,
                "jobs inspected",
            )?;
            add(
                &mut totals.jobs_accepted,
                record.jobs_accepted,
                "jobs accepted",
            )?;
            add(
                &mut totals.claims_evaluated,
                record.claims_evaluated,
                "claims evaluated",
            )?;
            add(
                &mut totals.evidence_bytes,
                record.evidence_bytes,
                "evidence bytes",
            )?;
            compute_units.add(record.compute_units, "compute units")?;
        }

        totals.input_tokens = input_tokens.finish();
        totals.output_tokens = output_tokens.finish();
        totals.cpu_time_ms = cpu_time_ms.finish();
        totals.compute_units = compute_units.finish();
        Ok(totals)
    }
}

#[derive(Default)]
pub(crate) struct OptionalAccumulator {
    known_total: u64,
    unavailable_records: u64,
}

impl OptionalAccumulator {
    pub(crate) fn add(
        &mut self,
        value: Option<u64>,
        counter: &'static str,
    ) -> Result<(), ResourceAccountingError> {
        match value {
            Some(value) => add(&mut self.known_total, value, counter),
            None => add(&mut self.unavailable_records, 1, "unavailable record count"),
        }
    }

    pub(crate) const fn finish(self) -> AvailabilityTotal {
        if self.unavailable_records == 0 {
            AvailabilityTotal::Complete {
                total: self.known_total,
            }
        } else {
            AvailabilityTotal::Partial {
                known_total: self.known_total,
                unavailable_records: self.unavailable_records,
            }
        }
    }
}

pub(crate) fn add(
    total: &mut u64,
    value: u64,
    counter: &'static str,
) -> Result<(), ResourceAccountingError> {
    *total = total
        .checked_add(value)
        .ok_or(ResourceAccountingError::CounterOverflow(counter))?;
    Ok(())
}

pub(crate) fn validate_identifier(
    subject: &'static str,
    value: &str,
) -> Result<(), ResourceAccountingError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ResourceAccountingError::InvalidIdentifier(subject));
    }
    Ok(())
}

/// Stable failures from resource reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceAccountingError {
    InvalidIdentifier(&'static str),
    CounterOverflow(&'static str),
    UnsupportedSchemaVersion(u32),
    TotalsMismatch,
}

impl fmt::Display for ResourceAccountingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(subject) => {
                write!(
                    formatter,
                    "{subject} must be 1..=512 bytes without control characters"
                )
            }
            Self::CounterOverflow(counter) => write!(formatter, "{counter} total overflowed u64"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "resource schema version {version} is not supported"
                )
            }
            Self::TotalsMismatch => formatter.write_str("resource totals do not reconcile"),
        }
    }
}

impl Error for ResourceAccountingError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(operator: &str, value: u64) -> ResourceRecord {
        ResourceRecord {
            operator: operator.to_owned(),
            epoch: value,
            model_calls: value,
            input_tokens: Some(value * 10),
            output_tokens: Some(value * 2),
            tool_calls: value + 1,
            command_duration_ms: value * 100,
            cpu_time_ms: Some(value * 80),
            validation_wall_clock_allowance_ms: value * 1_000,
            git_objects_read: value + 2,
            files_inspected: value + 3,
            tests_executed: value + 4,
            jobs_inspected: value + 5,
            jobs_accepted: value + 6,
            claims_evaluated: value + 7,
            evidence_bytes: value * 1_024,
            compute_units: Some(value * 4),
        }
    }

    #[test]
    fn totals_reconcile_exactly_and_tampering_is_detected() {
        let accounting = ResourceAccounting::from_records(vec![
            record("operator-a", 1),
            record("operator-b", 2),
        ])
        .unwrap();
        assert_eq!(
            accounting.totals,
            ResourceTotals {
                records: 2,
                model_calls: 3,
                input_tokens: AvailabilityTotal::Complete { total: 30 },
                output_tokens: AvailabilityTotal::Complete { total: 6 },
                tool_calls: 5,
                command_duration_ms: 300,
                cpu_time_ms: AvailabilityTotal::Complete { total: 240 },
                validation_wall_clock_allowance_ms: 3_000,
                git_objects_read: 7,
                files_inspected: 9,
                tests_executed: 11,
                jobs_inspected: 13,
                jobs_accepted: 15,
                claims_evaluated: 17,
                evidence_bytes: 3_072,
                compute_units: AvailabilityTotal::Complete { total: 12 },
            }
        );
        assert_eq!(accounting.by_operator.len(), 2);
        assert_eq!(accounting.by_operator[0].operator, "operator-a");
        assert_eq!(accounting.by_operator[0].totals.model_calls, 1);
        accounting.verify().unwrap();
        let encoded = accounting.to_json_bytes().unwrap();
        let decoded: ResourceAccounting = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, accounting);

        let mut tampered = accounting;
        tampered.totals.model_calls += 1;
        assert_eq!(
            tampered.verify(),
            Err(ResourceAccountingError::TotalsMismatch)
        );
    }

    #[test]
    fn unavailable_host_counters_are_explicit_without_discarding_known_values() {
        let first = record("operator-a", 1);
        let mut second = record("operator-a", 2);
        second.input_tokens = None;
        second.cpu_time_ms = None;
        second.compute_units = None;
        let totals = ResourceAccounting::from_records(vec![first, second])
            .unwrap()
            .totals;

        assert_eq!(
            totals.input_tokens,
            AvailabilityTotal::Partial {
                known_total: 10,
                unavailable_records: 1,
            }
        );
        assert_eq!(
            totals.cpu_time_ms,
            AvailabilityTotal::Partial {
                known_total: 80,
                unavailable_records: 1,
            }
        );
        assert_eq!(
            totals.compute_units,
            AvailabilityTotal::Partial {
                known_total: 4,
                unavailable_records: 1,
            }
        );
    }

    #[test]
    fn overflow_is_rejected_instead_of_wrapping() {
        let mut first = record("operator-a", 1);
        first.model_calls = u64::MAX;
        let mut second = record("operator-a", 1);
        second.model_calls = 1;
        assert_eq!(
            ResourceAccounting::from_records(vec![first, second]),
            Err(ResourceAccountingError::CounterOverflow("model calls"))
        );
    }
}
