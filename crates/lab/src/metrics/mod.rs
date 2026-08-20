//! Section 36 resource accounting and section 47 diagnostic laboratory metrics.
//!
//! Resource artifacts retain raw records beside checked, reproducible totals.
//! Metric artifacts use exact integer ratios and are explicitly diagnostic;
//! canonical outcomes remain in retained protocol state, blocks, and events.

mod report;
mod resource;

pub use report::{
    ChallengeActivity, ChallengeOutcome, ChallengeRecord, CounterpartyEdge, CounterpartyGraph,
    CounterpartyRecord, ExploitProfit, ExploitProfitability, ExploitRecord,
    JobSelectionDistribution, JobSelectionMetric, JobSelectionRecord, LaboratoryMetricInput,
    LaboratoryMetricReport, MetricError, OperatorValidationSummary, RatioMetric,
    RatioUnavailableReason, ReputationConcentration, ReputationEfficiency, ReputationMetrics,
    ReputationSnapshot, SignedRatioMetric, SignedValue, UsefulFindingRecord, ValidationMetricSet,
    ValidationRecord, ValidationSummary, ValidationTruth, ValidationVerdict,
};
pub use resource::{
    AvailabilityTotal, OperatorResourceTotals, ResourceAccounting, ResourceAccountingError,
    ResourceRecord, ResourceTotals,
};
