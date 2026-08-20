//! Diagnostic section 47 laboratory metrics derived from retained records.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::{Deserialize, Serialize};

use super::resource::{
    AvailabilityTotal, OptionalAccumulator, ResourceAccounting, ResourceAccountingError,
    ResourceTotals, add, validate_identifier,
};

const METRIC_SCHEMA_VERSION: u32 = 1;

/// A ratio retained as exact integer components rather than a rounded float.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RatioMetric {
    Defined { numerator: u64, denominator: u64 },
    Unavailable { reason: RatioUnavailableReason },
}

impl RatioMetric {
    const fn new(numerator: u64, denominator: u64) -> Self {
        if denominator == 0 {
            Self::Unavailable {
                reason: RatioUnavailableReason::ZeroDenominator,
            }
        } else {
            Self::Defined {
                numerator,
                denominator,
            }
        }
    }
}

/// JSON-portable sign and magnitude for values spanning `-u64::MAX..=u64::MAX`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedValue {
    pub negative: bool,
    pub magnitude: u64,
}

impl SignedValue {
    const fn from_i64(value: i64) -> Self {
        Self {
            negative: value.is_negative(),
            magnitude: value.unsigned_abs(),
        }
    }

    const fn difference(positive: u64, negative: u64) -> Self {
        if positive >= negative {
            Self {
                negative: false,
                magnitude: positive - negative,
            }
        } else {
            Self {
                negative: true,
                magnitude: negative - positive,
            }
        }
    }
}

/// A signed exact ratio, used for reputation efficiency and exploit return.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignedRatioMetric {
    Defined {
        numerator: SignedValue,
        denominator: u64,
    },
    Unavailable {
        reason: RatioUnavailableReason,
    },
}

impl SignedRatioMetric {
    const fn new(numerator: SignedValue, denominator: u64) -> Self {
        if denominator == 0 {
            Self::Unavailable {
                reason: RatioUnavailableReason::ZeroDenominator,
            }
        } else {
            Self::Defined {
                numerator,
                denominator,
            }
        }
    }
}

/// Why a diagnostic ratio cannot be computed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RatioUnavailableReason {
    ZeroDenominator,
    IncompleteResourceCounter,
}

/// Private ground truth used only after operator decisions have closed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationTruth {
    Pass,
    Fail,
    Unresolved,
}

/// One operator verdict compared with hidden evaluator truth.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRecord {
    pub epoch: u64,
    pub operator: String,
    pub job: String,
    pub claim: String,
    pub verdict: ValidationVerdict,
    pub truth: ValidationTruth,
}

/// Diagnostic projection of protocol verdicts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationVerdict {
    Pass,
    Fail,
    Abstain,
    Indeterminate,
}

/// Jobs visible and selected at one decision point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSelectionRecord {
    pub epoch: u64,
    pub operator: String,
    pub available_jobs: Vec<String>,
    pub selected_job: Option<String>,
}

/// Reputation observed from retained economic state at an epoch boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationSnapshot {
    pub epoch: u64,
    pub operator: String,
    /// Signed mechanism score observed in retained economic state.
    pub reputation: i64,
}

/// Useful findings are preregistered findings, not arbitrary evidence volume.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsefulFindingRecord {
    pub epoch: u64,
    pub operator: String,
    pub findings: u64,
}

/// One directed economic or validation interaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CounterpartyRecord {
    pub source: String,
    pub target: String,
    pub interactions: u64,
    pub jobs: u64,
    pub claims: u64,
    pub evidence_bytes: u64,
}

/// Revenue and cost attributable to one attempted exploit strategy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitRecord {
    pub operator: String,
    pub strategy: String,
    pub attempts: u64,
    pub successes: u64,
    pub revenue_microunits: u64,
    pub cost_microunits: u64,
}

/// Terminal state of one challenge at report time.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeOutcome {
    Open,
    Upheld,
    Rejected,
}

/// One challenge and its terminal state at report time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRecord {
    pub epoch: u64,
    pub challenger: String,
    pub target: String,
    pub outcome: ChallengeOutcome,
}

/// Complete raw input to diagnostic metric derivation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaboratoryMetricInput {
    pub validations: Vec<ValidationRecord>,
    pub job_selections: Vec<JobSelectionRecord>,
    pub reputation: Vec<ReputationSnapshot>,
    pub useful_findings: Vec<UsefulFindingRecord>,
    pub counterparties: Vec<CounterpartyRecord>,
    pub exploits: Vec<ExploitRecord>,
    pub challenges: Vec<ChallengeRecord>,
}

/// Correctness and error counts for one population.
///
/// Correctness and error rates cover PASS/FAIL decisions against binary truth;
/// abstention and unresolved-truth behavior remain separate diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationSummary {
    pub evaluated: u64,
    pub binary_decisions: u64,
    pub correct: u64,
    pub incorrect: u64,
    pub false_passes: u64,
    pub false_fails: u64,
    pub abstentions: u64,
    pub indeterminate: u64,
    pub unresolved_truth: u64,
    pub decisive_on_unresolved: u64,
    pub correctness: RatioMetric,
    pub error_rate: RatioMetric,
    pub false_pass_rate: RatioMetric,
    pub false_fail_rate: RatioMetric,
    pub abstention_quality: RatioMetric,
    pub unresolved_abstention_coverage: RatioMetric,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorValidationSummary {
    pub operator: String,
    pub summary: ValidationSummary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationMetricSet {
    pub overall: ValidationSummary,
    pub by_operator: Vec<OperatorValidationSummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSelectionMetric {
    pub job: String,
    pub available_decisions: u64,
    pub selections: u64,
    pub selection_rate: RatioMetric,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSelectionDistribution {
    pub decisions: u64,
    pub no_selection: u64,
    pub jobs: Vec<JobSelectionMetric>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationEfficiency {
    pub epoch: u64,
    pub operator: String,
    pub reputation: i64,
    pub compute_units: AvailabilityTotal,
    pub useful_findings: u64,
    pub reputation_per_compute_unit: SignedRatioMetric,
    pub reputation_per_useful_finding: SignedRatioMetric,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationConcentration {
    pub epoch: u64,
    pub operators: u64,
    pub net_reputation: SignedValue,
    /// Sum of positive scores used as the concentration mass.
    pub positive_reputation: u64,
    /// Zero and negative scores cannot own a share of positive reputation.
    pub nonpositive_operators: u64,
    /// Herfindahl-Hirschman index over positive scores only.
    pub hhi: RatioMetric,
    pub largest_operator_share: RatioMetric,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationMetrics {
    pub by_epoch: Vec<ReputationSnapshot>,
    pub efficiency: Vec<ReputationEfficiency>,
    pub concentration: Vec<ReputationConcentration>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CounterpartyEdge {
    pub source: String,
    pub target: String,
    pub interactions: u64,
    pub jobs: u64,
    pub claims: u64,
    pub evidence_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CounterpartyGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<CounterpartyEdge>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitProfit {
    pub operator: Option<String>,
    pub strategy: Option<String>,
    pub attempts: u64,
    pub successes: u64,
    pub revenue_microunits: u64,
    pub cost_microunits: u64,
    pub profit_microunits: SignedValue,
    pub success_rate: RatioMetric,
    pub return_on_cost: SignedRatioMetric,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitProfitability {
    pub overall: ExploitProfit,
    pub by_operator_and_strategy: Vec<ExploitProfit>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeActivity {
    pub total: u64,
    pub open: u64,
    pub resolved: u64,
    pub upheld: u64,
    pub rejected: u64,
    pub upheld_rate: RatioMetric,
    pub unique_challengers: u64,
    pub unique_targets: u64,
}

/// Derived `metrics.json`. These values are explicitly non-canonical.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaboratoryMetricReport {
    pub schema_version: u32,
    pub diagnostic_only: bool,
    pub resource_use: ResourceTotals,
    pub validation: ValidationMetricSet,
    pub job_selection: JobSelectionDistribution,
    pub reputation: ReputationMetrics,
    pub counterparty_graph: CounterpartyGraph,
    pub exploit_profitability: ExploitProfitability,
    pub challenge_activity: ChallengeActivity,
}

impl LaboratoryMetricReport {
    /// Derives all metrics from retained records. No result feeds protocol state.
    pub fn derive(
        input: &LaboratoryMetricInput,
        resources: &ResourceAccounting,
    ) -> Result<Self, MetricError> {
        resources.verify().map_err(MetricError::Resource)?;
        validate_input(input)?;
        Ok(Self {
            schema_version: METRIC_SCHEMA_VERSION,
            diagnostic_only: true,
            resource_use: resources.totals.clone(),
            validation: validation_metrics(&input.validations)?,
            job_selection: selection_metrics(&input.job_selections)?,
            reputation: reputation_metrics(
                &input.reputation,
                &input.useful_findings,
                &resources.records,
            )?,
            counterparty_graph: counterparty_graph(&input.counterparties)?,
            exploit_profitability: exploit_metrics(&input.exploits)?,
            challenge_activity: challenge_metrics(&input.challenges)?,
        })
    }

    /// Enforces the diagnostic marker when loading a retained report.
    pub fn verify_diagnostic_marker(&self) -> Result<(), MetricError> {
        if self.schema_version != METRIC_SCHEMA_VERSION {
            return Err(MetricError::UnsupportedSchemaVersion(self.schema_version));
        }
        if !self.diagnostic_only {
            return Err(MetricError::CanonicalMetricClaim);
        }
        Ok(())
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

fn validate_input(input: &LaboratoryMetricInput) -> Result<(), MetricError> {
    for record in &input.validations {
        identifier("validation operator", &record.operator)?;
        identifier("validation job", &record.job)?;
        identifier("validation claim", &record.claim)?;
    }
    for record in &input.job_selections {
        identifier("selection operator", &record.operator)?;
        for job in &record.available_jobs {
            identifier("available job", job)?;
        }
        if let Some(job) = &record.selected_job {
            identifier("selected job", job)?;
        }
    }
    for record in &input.reputation {
        identifier("reputation operator", &record.operator)?;
    }
    for record in &input.useful_findings {
        identifier("finding operator", &record.operator)?;
    }
    for record in &input.counterparties {
        identifier("counterparty source", &record.source)?;
        identifier("counterparty target", &record.target)?;
    }
    for record in &input.exploits {
        identifier("exploit operator", &record.operator)?;
        identifier("exploit strategy", &record.strategy)?;
        if record.successes > record.attempts {
            return Err(MetricError::SuccessesExceedAttempts);
        }
    }
    for record in &input.challenges {
        identifier("challenger", &record.challenger)?;
        identifier("challenge target", &record.target)?;
    }
    Ok(())
}

fn identifier(subject: &'static str, value: &str) -> Result<(), MetricError> {
    validate_identifier(subject, value).map_err(MetricError::Resource)
}

#[derive(Default)]
struct ValidationAccumulator {
    evaluated: u64,
    binary_decisions: u64,
    correct: u64,
    incorrect: u64,
    false_passes: u64,
    false_fails: u64,
    abstentions: u64,
    appropriate_abstentions: u64,
    indeterminate: u64,
    truth_pass: u64,
    truth_fail: u64,
    unresolved_truth: u64,
    decisive_on_unresolved: u64,
}

impl ValidationAccumulator {
    fn include(&mut self, record: &ValidationRecord) -> Result<(), MetricError> {
        metric_add(&mut self.evaluated, 1, "validations evaluated")?;
        match record.truth {
            ValidationTruth::Pass => metric_add(&mut self.truth_pass, 1, "PASS truth")?,
            ValidationTruth::Fail => metric_add(&mut self.truth_fail, 1, "FAIL truth")?,
            ValidationTruth::Unresolved => {
                metric_add(&mut self.unresolved_truth, 1, "unresolved truth")?;
            }
        }
        match record.verdict {
            ValidationVerdict::Abstain => {
                metric_add(&mut self.abstentions, 1, "abstentions")?;
                if record.truth == ValidationTruth::Unresolved {
                    metric_add(
                        &mut self.appropriate_abstentions,
                        1,
                        "appropriate abstentions",
                    )?;
                }
            }
            ValidationVerdict::Indeterminate => {
                metric_add(&mut self.indeterminate, 1, "indeterminate verdicts")?;
            }
            ValidationVerdict::Pass | ValidationVerdict::Fail => {
                if record.truth == ValidationTruth::Unresolved {
                    metric_add(
                        &mut self.decisive_on_unresolved,
                        1,
                        "decisive unresolved verdicts",
                    )?;
                } else {
                    metric_add(&mut self.binary_decisions, 1, "binary decisions")?;
                    let correct = matches!(
                        (record.verdict, record.truth),
                        (ValidationVerdict::Pass, ValidationTruth::Pass)
                            | (ValidationVerdict::Fail, ValidationTruth::Fail)
                    );
                    if correct {
                        metric_add(&mut self.correct, 1, "correct validations")?;
                    } else {
                        metric_add(&mut self.incorrect, 1, "incorrect validations")?;
                        if record.verdict == ValidationVerdict::Pass {
                            metric_add(&mut self.false_passes, 1, "false passes")?;
                        } else {
                            metric_add(&mut self.false_fails, 1, "false fails")?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    const fn finish(self) -> ValidationSummary {
        ValidationSummary {
            evaluated: self.evaluated,
            binary_decisions: self.binary_decisions,
            correct: self.correct,
            incorrect: self.incorrect,
            false_passes: self.false_passes,
            false_fails: self.false_fails,
            abstentions: self.abstentions,
            indeterminate: self.indeterminate,
            unresolved_truth: self.unresolved_truth,
            decisive_on_unresolved: self.decisive_on_unresolved,
            correctness: RatioMetric::new(self.correct, self.binary_decisions),
            error_rate: RatioMetric::new(self.incorrect, self.binary_decisions),
            false_pass_rate: RatioMetric::new(self.false_passes, self.truth_fail),
            false_fail_rate: RatioMetric::new(self.false_fails, self.truth_pass),
            abstention_quality: RatioMetric::new(self.appropriate_abstentions, self.abstentions),
            unresolved_abstention_coverage: RatioMetric::new(
                self.appropriate_abstentions,
                self.unresolved_truth,
            ),
        }
    }
}

fn validation_metrics(records: &[ValidationRecord]) -> Result<ValidationMetricSet, MetricError> {
    let mut overall = ValidationAccumulator::default();
    let mut operators: BTreeMap<String, ValidationAccumulator> = BTreeMap::new();
    for record in records {
        overall.include(record)?;
        operators
            .entry(record.operator.clone())
            .or_default()
            .include(record)?;
    }
    Ok(ValidationMetricSet {
        overall: overall.finish(),
        by_operator: operators
            .into_iter()
            .map(|(operator, summary)| OperatorValidationSummary {
                operator,
                summary: summary.finish(),
            })
            .collect(),
    })
}

fn selection_metrics(
    records: &[JobSelectionRecord],
) -> Result<JobSelectionDistribution, MetricError> {
    let mut decisions = 0;
    let mut no_selection = 0;
    let mut jobs: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for record in records {
        metric_add(&mut decisions, 1, "selection decisions")?;
        let available: BTreeSet<_> = record.available_jobs.iter().collect();
        if available.len() != record.available_jobs.len() {
            return Err(MetricError::DuplicateAvailableJob);
        }
        if let Some(selected) = &record.selected_job {
            if !available.contains(selected) {
                return Err(MetricError::SelectedJobUnavailable);
            }
        } else {
            metric_add(&mut no_selection, 1, "no-selection decisions")?;
        }
        for job in available {
            let entry = jobs.entry(job.clone()).or_default();
            metric_add(&mut entry.0, 1, "job availability")?;
            if record.selected_job.as_ref() == Some(job) {
                metric_add(&mut entry.1, 1, "job selections")?;
            }
        }
    }
    Ok(JobSelectionDistribution {
        decisions,
        no_selection,
        jobs: jobs
            .into_iter()
            .map(
                |(job, (available_decisions, selections))| JobSelectionMetric {
                    job,
                    available_decisions,
                    selections,
                    selection_rate: RatioMetric::new(selections, available_decisions),
                },
            )
            .collect(),
    })
}

fn reputation_metrics(
    snapshots: &[ReputationSnapshot],
    findings: &[UsefulFindingRecord],
    resources: &[super::resource::ResourceRecord],
) -> Result<ReputationMetrics, MetricError> {
    let mut ordered: BTreeMap<(u64, String), i64> = BTreeMap::new();
    for snapshot in snapshots {
        if ordered
            .insert(
                (snapshot.epoch, snapshot.operator.clone()),
                snapshot.reputation,
            )
            .is_some()
        {
            return Err(MetricError::DuplicateReputationSnapshot);
        }
    }

    let mut finding_totals: BTreeMap<(u64, String), u64> = BTreeMap::new();
    for finding in findings {
        let total = finding_totals
            .entry((finding.epoch, finding.operator.clone()))
            .or_default();
        metric_add(total, finding.findings, "useful findings")?;
    }

    let mut compute: BTreeMap<(u64, String), OptionalAccumulator> = BTreeMap::new();
    for record in resources {
        compute
            .entry((record.epoch, record.operator.clone()))
            .or_default()
            .add(record.compute_units, "compute units")
            .map_err(MetricError::Resource)?;
    }

    let by_epoch: Vec<_> = ordered
        .iter()
        .map(|((epoch, operator), reputation)| ReputationSnapshot {
            epoch: *epoch,
            operator: operator.clone(),
            reputation: *reputation,
        })
        .collect();
    let mut efficiency = Vec::with_capacity(by_epoch.len());
    for snapshot in &by_epoch {
        let key = (snapshot.epoch, snapshot.operator.clone());
        let compute_units = compute.remove(&key).map_or(
            AvailabilityTotal::Complete { total: 0 },
            OptionalAccumulator::finish,
        );
        let useful_findings = finding_totals.get(&key).copied().unwrap_or(0);
        let reputation_per_compute_unit = match compute_units {
            AvailabilityTotal::Complete { total } => {
                SignedRatioMetric::new(SignedValue::from_i64(snapshot.reputation), total)
            }
            AvailabilityTotal::Partial { .. } => SignedRatioMetric::Unavailable {
                reason: RatioUnavailableReason::IncompleteResourceCounter,
            },
        };
        efficiency.push(ReputationEfficiency {
            epoch: snapshot.epoch,
            operator: snapshot.operator.clone(),
            reputation: snapshot.reputation,
            compute_units,
            useful_findings,
            reputation_per_compute_unit,
            reputation_per_useful_finding: SignedRatioMetric::new(
                SignedValue::from_i64(snapshot.reputation),
                useful_findings,
            ),
        });
    }

    let mut epochs: BTreeMap<u64, Vec<i64>> = BTreeMap::new();
    for snapshot in &by_epoch {
        epochs
            .entry(snapshot.epoch)
            .or_default()
            .push(snapshot.reputation);
    }
    let mut concentration = Vec::with_capacity(epochs.len());
    for (epoch, reputations) in epochs {
        let mut positive_reputation = 0_u64;
        let mut negative_reputation = 0_u64;
        let mut nonpositive_operators = 0_u64;
        let mut squares = 0_u64;
        let mut largest = 0_u64;
        for reputation in &reputations {
            if *reputation <= 0 {
                metric_add(&mut nonpositive_operators, 1, "nonpositive operator count")?;
                metric_add(
                    &mut negative_reputation,
                    reputation.unsigned_abs(),
                    "negative reputation magnitude",
                )?;
                continue;
            }
            let positive = u64::try_from(*reputation)
                .map_err(|_| MetricError::CounterOverflow("positive reputation"))?;
            metric_add(
                &mut positive_reputation,
                positive,
                "positive epoch reputation",
            )?;
            let square = positive
                .checked_mul(positive)
                .ok_or(MetricError::CounterOverflow("reputation square"))?;
            metric_add(&mut squares, square, "reputation square sum")?;
            largest = largest.max(positive);
        }
        let denominator = positive_reputation
            .checked_mul(positive_reputation)
            .ok_or(MetricError::CounterOverflow("reputation total square"))?;
        concentration.push(ReputationConcentration {
            epoch,
            operators: u64::try_from(reputations.len())
                .map_err(|_| MetricError::CounterOverflow("operator count"))?,
            net_reputation: SignedValue::difference(positive_reputation, negative_reputation),
            positive_reputation,
            nonpositive_operators,
            hhi: RatioMetric::new(squares, denominator),
            largest_operator_share: RatioMetric::new(largest, positive_reputation),
        });
    }

    Ok(ReputationMetrics {
        by_epoch,
        efficiency,
        concentration,
    })
}

fn counterparty_graph(records: &[CounterpartyRecord]) -> Result<CounterpartyGraph, MetricError> {
    let mut nodes = BTreeSet::new();
    let mut edges: BTreeMap<(String, String), (u64, u64, u64, u64)> = BTreeMap::new();
    for record in records {
        nodes.insert(record.source.clone());
        nodes.insert(record.target.clone());
        let edge = edges
            .entry((record.source.clone(), record.target.clone()))
            .or_default();
        metric_add(
            &mut edge.0,
            record.interactions,
            "counterparty interactions",
        )?;
        metric_add(&mut edge.1, record.jobs, "counterparty jobs")?;
        metric_add(&mut edge.2, record.claims, "counterparty claims")?;
        metric_add(
            &mut edge.3,
            record.evidence_bytes,
            "counterparty evidence bytes",
        )?;
    }
    Ok(CounterpartyGraph {
        nodes: nodes.into_iter().collect(),
        edges: edges
            .into_iter()
            .map(
                |((source, target), (interactions, jobs, claims, evidence_bytes))| {
                    CounterpartyEdge {
                        source,
                        target,
                        interactions,
                        jobs,
                        claims,
                        evidence_bytes,
                    }
                },
            )
            .collect(),
    })
}

#[derive(Default)]
struct ExploitAccumulator {
    attempts: u64,
    successes: u64,
    revenue: u64,
    cost: u64,
}

impl ExploitAccumulator {
    fn include(&mut self, record: &ExploitRecord) -> Result<(), MetricError> {
        metric_add(&mut self.attempts, record.attempts, "exploit attempts")?;
        metric_add(&mut self.successes, record.successes, "exploit successes")?;
        metric_add(
            &mut self.revenue,
            record.revenue_microunits,
            "exploit revenue",
        )?;
        metric_add(&mut self.cost, record.cost_microunits, "exploit cost")
    }

    fn finish(self, operator: Option<String>, strategy: Option<String>) -> ExploitProfit {
        let profit = SignedValue::difference(self.revenue, self.cost);
        ExploitProfit {
            operator,
            strategy,
            attempts: self.attempts,
            successes: self.successes,
            revenue_microunits: self.revenue,
            cost_microunits: self.cost,
            profit_microunits: profit,
            success_rate: RatioMetric::new(self.successes, self.attempts),
            return_on_cost: SignedRatioMetric::new(profit, self.cost),
        }
    }
}

fn exploit_metrics(records: &[ExploitRecord]) -> Result<ExploitProfitability, MetricError> {
    let mut overall = ExploitAccumulator::default();
    let mut groups: BTreeMap<(String, String), ExploitAccumulator> = BTreeMap::new();
    for record in records {
        overall.include(record)?;
        groups
            .entry((record.operator.clone(), record.strategy.clone()))
            .or_default()
            .include(record)?;
    }
    Ok(ExploitProfitability {
        overall: overall.finish(None, None),
        by_operator_and_strategy: groups
            .into_iter()
            .map(|((operator, strategy), totals)| totals.finish(Some(operator), Some(strategy)))
            .collect(),
    })
}

fn challenge_metrics(records: &[ChallengeRecord]) -> Result<ChallengeActivity, MetricError> {
    let mut total = 0;
    let mut open = 0;
    let mut upheld = 0;
    let mut rejected = 0;
    let mut challengers = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for record in records {
        metric_add(&mut total, 1, "challenges")?;
        challengers.insert(&record.challenger);
        targets.insert(&record.target);
        match record.outcome {
            ChallengeOutcome::Open => metric_add(&mut open, 1, "open challenges")?,
            ChallengeOutcome::Upheld => metric_add(&mut upheld, 1, "upheld challenges")?,
            ChallengeOutcome::Rejected => metric_add(&mut rejected, 1, "rejected challenges")?,
        }
    }
    let resolved = upheld
        .checked_add(rejected)
        .ok_or(MetricError::CounterOverflow("resolved challenges"))?;
    Ok(ChallengeActivity {
        total,
        open,
        resolved,
        upheld,
        rejected,
        upheld_rate: RatioMetric::new(upheld, resolved),
        unique_challengers: u64::try_from(challengers.len())
            .map_err(|_| MetricError::CounterOverflow("unique challengers"))?,
        unique_targets: u64::try_from(targets.len())
            .map_err(|_| MetricError::CounterOverflow("unique challenge targets"))?,
    })
}

fn metric_add(total: &mut u64, value: u64, counter: &'static str) -> Result<(), MetricError> {
    add(total, value, counter).map_err(|error| match error {
        ResourceAccountingError::CounterOverflow(counter) => MetricError::CounterOverflow(counter),
        other => MetricError::Resource(other),
    })
}

/// Stable failures from diagnostic metric derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricError {
    Resource(ResourceAccountingError),
    CounterOverflow(&'static str),
    DuplicateAvailableJob,
    SelectedJobUnavailable,
    DuplicateReputationSnapshot,
    SuccessesExceedAttempts,
    UnsupportedSchemaVersion(u32),
    CanonicalMetricClaim,
}

impl fmt::Display for MetricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource(error) => write!(formatter, "invalid resource accounting: {error}"),
            Self::CounterOverflow(counter) => write!(formatter, "{counter} total overflowed u64"),
            Self::DuplicateAvailableJob => {
                formatter.write_str("selection record contains a duplicate available job")
            }
            Self::SelectedJobUnavailable => {
                formatter.write_str("selected job was not in the available job set")
            }
            Self::DuplicateReputationSnapshot => {
                formatter.write_str("operator has duplicate reputation snapshots for one epoch")
            }
            Self::SuccessesExceedAttempts => {
                formatter.write_str("exploit successes exceed attempts")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "metric schema version {version} is not supported"
                )
            }
            Self::CanonicalMetricClaim => {
                formatter.write_str("laboratory metrics must remain diagnostic-only")
            }
        }
    }
}

impl Error for MetricError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::ResourceRecord;

    fn resource(operator: &str, epoch: u64, compute_units: Option<u64>) -> ResourceRecord {
        ResourceRecord {
            operator: operator.to_owned(),
            epoch,
            model_calls: 1,
            input_tokens: Some(10),
            output_tokens: Some(2),
            tool_calls: 2,
            command_duration_ms: 100,
            cpu_time_ms: Some(80),
            validation_wall_clock_allowance_ms: 1_000,
            git_objects_read: 3,
            files_inspected: 4,
            tests_executed: 5,
            jobs_inspected: 6,
            jobs_accepted: 1,
            claims_evaluated: 2,
            evidence_bytes: 512,
            compute_units,
        }
    }

    fn validation(
        operator: &str,
        claim: &str,
        verdict: ValidationVerdict,
        truth: ValidationTruth,
    ) -> ValidationRecord {
        ValidationRecord {
            epoch: 7,
            operator: operator.to_owned(),
            job: "job-a".to_owned(),
            claim: claim.to_owned(),
            verdict,
            truth,
        }
    }

    #[test]
    fn exact_fixture_covers_correctness_selection_reputation_and_challenges() {
        let resources = ResourceAccounting::from_records(vec![
            resource("alice", 7, Some(4)),
            resource("bob", 7, Some(6)),
        ])
        .unwrap();
        let input = LaboratoryMetricInput {
            validations: vec![
                validation(
                    "alice",
                    "c1",
                    ValidationVerdict::Pass,
                    ValidationTruth::Pass,
                ),
                validation(
                    "alice",
                    "c2",
                    ValidationVerdict::Pass,
                    ValidationTruth::Fail,
                ),
                validation("bob", "c3", ValidationVerdict::Fail, ValidationTruth::Pass),
                validation("bob", "c4", ValidationVerdict::Fail, ValidationTruth::Fail),
                validation(
                    "alice",
                    "c5",
                    ValidationVerdict::Abstain,
                    ValidationTruth::Unresolved,
                ),
                validation(
                    "bob",
                    "c6",
                    ValidationVerdict::Abstain,
                    ValidationTruth::Pass,
                ),
                validation(
                    "bob",
                    "c7",
                    ValidationVerdict::Pass,
                    ValidationTruth::Unresolved,
                ),
                validation(
                    "alice",
                    "c8",
                    ValidationVerdict::Indeterminate,
                    ValidationTruth::Fail,
                ),
            ],
            job_selections: vec![
                JobSelectionRecord {
                    epoch: 7,
                    operator: "alice".to_owned(),
                    available_jobs: vec!["job-a".to_owned(), "job-b".to_owned()],
                    selected_job: Some("job-a".to_owned()),
                },
                JobSelectionRecord {
                    epoch: 7,
                    operator: "bob".to_owned(),
                    available_jobs: vec!["job-a".to_owned(), "job-b".to_owned()],
                    selected_job: Some("job-b".to_owned()),
                },
                JobSelectionRecord {
                    epoch: 7,
                    operator: "alice".to_owned(),
                    available_jobs: vec!["job-b".to_owned()],
                    selected_job: None,
                },
            ],
            reputation: vec![
                ReputationSnapshot {
                    epoch: 7,
                    operator: "alice".to_owned(),
                    reputation: 30,
                },
                ReputationSnapshot {
                    epoch: 7,
                    operator: "bob".to_owned(),
                    reputation: 10,
                },
            ],
            useful_findings: vec![
                UsefulFindingRecord {
                    epoch: 7,
                    operator: "alice".to_owned(),
                    findings: 3,
                },
                UsefulFindingRecord {
                    epoch: 7,
                    operator: "bob".to_owned(),
                    findings: 2,
                },
            ],
            counterparties: vec![
                CounterpartyRecord {
                    source: "alice".to_owned(),
                    target: "customer".to_owned(),
                    interactions: 1,
                    jobs: 1,
                    claims: 2,
                    evidence_bytes: 100,
                },
                CounterpartyRecord {
                    source: "alice".to_owned(),
                    target: "customer".to_owned(),
                    interactions: 2,
                    jobs: 0,
                    claims: 1,
                    evidence_bytes: 50,
                },
            ],
            exploits: vec![
                ExploitRecord {
                    operator: "alice".to_owned(),
                    strategy: "rubber-stamp".to_owned(),
                    attempts: 2,
                    successes: 1,
                    revenue_microunits: 90,
                    cost_microunits: 30,
                },
                ExploitRecord {
                    operator: "bob".to_owned(),
                    strategy: "copy-peer".to_owned(),
                    attempts: 1,
                    successes: 0,
                    revenue_microunits: 0,
                    cost_microunits: 20,
                },
            ],
            challenges: vec![
                ChallengeRecord {
                    epoch: 7,
                    challenger: "alice".to_owned(),
                    target: "claim-1".to_owned(),
                    outcome: ChallengeOutcome::Upheld,
                },
                ChallengeRecord {
                    epoch: 7,
                    challenger: "bob".to_owned(),
                    target: "claim-2".to_owned(),
                    outcome: ChallengeOutcome::Rejected,
                },
                ChallengeRecord {
                    epoch: 7,
                    challenger: "alice".to_owned(),
                    target: "claim-3".to_owned(),
                    outcome: ChallengeOutcome::Open,
                },
            ],
        };

        let report = LaboratoryMetricReport::derive(&input, &resources).unwrap();
        assert!(report.diagnostic_only);
        assert_eq!(
            report.validation.overall,
            ValidationSummary {
                evaluated: 8,
                binary_decisions: 4,
                correct: 2,
                incorrect: 2,
                false_passes: 1,
                false_fails: 1,
                abstentions: 2,
                indeterminate: 1,
                unresolved_truth: 2,
                decisive_on_unresolved: 1,
                correctness: RatioMetric::Defined {
                    numerator: 2,
                    denominator: 4,
                },
                error_rate: RatioMetric::Defined {
                    numerator: 2,
                    denominator: 4,
                },
                false_pass_rate: RatioMetric::Defined {
                    numerator: 1,
                    denominator: 3,
                },
                false_fail_rate: RatioMetric::Defined {
                    numerator: 1,
                    denominator: 3,
                },
                abstention_quality: RatioMetric::Defined {
                    numerator: 1,
                    denominator: 2,
                },
                unresolved_abstention_coverage: RatioMetric::Defined {
                    numerator: 1,
                    denominator: 2,
                },
            }
        );
        assert_eq!(report.job_selection.decisions, 3);
        assert_eq!(report.job_selection.no_selection, 1);
        assert_eq!(
            report.job_selection.jobs,
            vec![
                JobSelectionMetric {
                    job: "job-a".to_owned(),
                    available_decisions: 2,
                    selections: 1,
                    selection_rate: RatioMetric::Defined {
                        numerator: 1,
                        denominator: 2,
                    },
                },
                JobSelectionMetric {
                    job: "job-b".to_owned(),
                    available_decisions: 3,
                    selections: 1,
                    selection_rate: RatioMetric::Defined {
                        numerator: 1,
                        denominator: 3,
                    },
                },
            ]
        );
        assert_eq!(
            report.reputation.concentration,
            vec![ReputationConcentration {
                epoch: 7,
                operators: 2,
                net_reputation: SignedValue {
                    negative: false,
                    magnitude: 40,
                },
                positive_reputation: 40,
                nonpositive_operators: 0,
                hhi: RatioMetric::Defined {
                    numerator: 1_000,
                    denominator: 1_600,
                },
                largest_operator_share: RatioMetric::Defined {
                    numerator: 30,
                    denominator: 40,
                },
            }]
        );
        assert_eq!(
            report.reputation.efficiency[0].reputation_per_compute_unit,
            SignedRatioMetric::Defined {
                numerator: SignedValue {
                    negative: false,
                    magnitude: 30,
                },
                denominator: 4,
            }
        );
        assert_eq!(report.counterparty_graph.edges[0].interactions, 3);
        assert_eq!(report.counterparty_graph.edges[0].evidence_bytes, 150);
        assert_eq!(
            report.exploit_profitability.overall.profit_microunits,
            SignedValue {
                negative: false,
                magnitude: 40,
            }
        );
        assert_eq!(
            report.exploit_profitability.overall.return_on_cost,
            SignedRatioMetric::Defined {
                numerator: SignedValue {
                    negative: false,
                    magnitude: 40,
                },
                denominator: 50,
            }
        );
        assert_eq!(report.challenge_activity.total, 3);
        assert_eq!(report.challenge_activity.resolved, 2);
        assert_eq!(
            report.challenge_activity.upheld_rate,
            RatioMetric::Defined {
                numerator: 1,
                denominator: 2,
            }
        );
        report.verify_diagnostic_marker().unwrap();
        let encoded = report.to_json_bytes().unwrap();
        let decoded: LaboratoryMetricReport = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, report);
    }

    #[test]
    fn missing_compute_and_empty_denominators_remain_explicit() {
        let resources = ResourceAccounting::from_records(vec![resource("alice", 1, None)]).unwrap();
        let input = LaboratoryMetricInput {
            reputation: vec![ReputationSnapshot {
                epoch: 1,
                operator: "alice".to_owned(),
                reputation: -5,
            }],
            ..LaboratoryMetricInput::default()
        };
        let report = LaboratoryMetricReport::derive(&input, &resources).unwrap();
        assert_eq!(
            report.reputation.efficiency[0].compute_units,
            AvailabilityTotal::Partial {
                known_total: 0,
                unavailable_records: 1,
            }
        );
        assert_eq!(
            report.reputation.efficiency[0].reputation_per_compute_unit,
            SignedRatioMetric::Unavailable {
                reason: RatioUnavailableReason::IncompleteResourceCounter,
            }
        );
        assert_eq!(
            report.reputation.concentration[0].net_reputation,
            SignedValue {
                negative: true,
                magnitude: 5,
            }
        );
        assert_eq!(report.reputation.concentration[0].positive_reputation, 0);
        assert_eq!(report.reputation.concentration[0].nonpositive_operators, 1);
        assert_eq!(
            report.reputation.concentration[0].hhi,
            RatioMetric::Unavailable {
                reason: RatioUnavailableReason::ZeroDenominator,
            }
        );
        assert_eq!(
            report.validation.overall.correctness,
            RatioMetric::Unavailable {
                reason: RatioUnavailableReason::ZeroDenominator,
            }
        );
        assert_eq!(
            report.exploit_profitability.overall.return_on_cost,
            SignedRatioMetric::Unavailable {
                reason: RatioUnavailableReason::ZeroDenominator,
            }
        );
    }

    #[test]
    fn invalid_selection_and_diagnostic_claims_are_rejected() {
        let resources = ResourceAccounting::from_records(Vec::new()).unwrap();
        let input = LaboratoryMetricInput {
            job_selections: vec![JobSelectionRecord {
                epoch: 0,
                operator: "alice".to_owned(),
                available_jobs: vec!["job-a".to_owned()],
                selected_job: Some("job-b".to_owned()),
            }],
            ..LaboratoryMetricInput::default()
        };
        assert_eq!(
            LaboratoryMetricReport::derive(&input, &resources),
            Err(MetricError::SelectedJobUnavailable)
        );

        let mut report =
            LaboratoryMetricReport::derive(&LaboratoryMetricInput::default(), &resources).unwrap();
        report.diagnostic_only = false;
        assert_eq!(
            report.verify_diagnostic_marker(),
            Err(MetricError::CanonicalMetricClaim)
        );
    }
}
