//! Pure scripted validation-operator policies for deterministic laboratory runs.
//!
//! Every policy in this module is a trivial heuristic. None invokes a model,
//! tool, shell, network, repository, or evaluator truth, and none is a
//! resource-matched intelligent baseline. Inputs contain only public job data,
//! currently revealed validation-operator verdicts, and public history.

use std::{collections::BTreeSet, error::Error, fmt};

use rachet_core::{
    actions::Verdict,
    limits::MAX_CLAIMS_PER_JOB,
    primitives::{ClaimId, JobId},
};

/// Maximum jobs admitted by the `operator-observation.v1` host contract.
pub const MAX_AVAILABLE_JOBS: usize = 1_024;

/// Fixed classification carried by every scripted policy in this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyClassification {
    /// A control heuristic with no claim to intelligent, resource-matched work.
    TrivialHeuristic,
}

/// Auditable metadata that prevents scripted controls from being mislabeled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyMetadata {
    id: &'static str,
    classification: PolicyClassification,
    resource_matched_intelligent_baseline: bool,
}

impl PolicyMetadata {
    pub const fn id(self) -> &'static str {
        self.id
    }

    pub const fn classification(self) -> PolicyClassification {
        self.classification
    }

    pub const fn is_resource_matched_intelligent_baseline(self) -> bool {
        self.resource_matched_intelligent_baseline
    }
}

/// The required deterministic scripted and fixed-heuristic policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptedPolicy {
    AlwaysPass,
    AlwaysFail,
    /// Pseudorandom PASS/FAIL decisions derived solely from this explicit seed
    /// and stable public decision-point identifiers.
    RandomVerdict {
        seed: u64,
    },
    TrivialJobsOnly,
    /// Follows the current majority of revealed validation-operator verdicts.
    /// This has no relationship to Commonware consensus nodes or votes.
    ConsensusFollower,
    MaximumVolume,
    PerfectAbstainer,
    HistoricalMajorityFollower,
}

impl ScriptedPolicy {
    /// Returns the immutable control classification for reporting.
    pub const fn metadata(self) -> PolicyMetadata {
        PolicyMetadata {
            id: match self {
                Self::AlwaysPass => "always-pass",
                Self::AlwaysFail => "always-fail",
                Self::RandomVerdict { .. } => "random-verdict",
                Self::TrivialJobsOnly => "trivial-jobs-only",
                Self::ConsensusFollower => "consensus-follower",
                Self::MaximumVolume => "maximum-volume",
                Self::PerfectAbstainer => "perfect-abstainer",
                Self::HistoricalMajorityFollower => "historical-majority-follower",
            },
            classification: PolicyClassification::TrivialHeuristic,
            resource_matched_intelligent_baseline: false,
        }
    }

    /// Produces one pure decision from one immutable public observation.
    pub fn decide(self, observation: &PolicyObservation) -> ScriptedDecision {
        let selected = match self {
            Self::TrivialJobsOnly => observation.jobs.iter().find(|job| job.publicly_trivial),
            Self::MaximumVolume => largest_job(&observation.jobs),
            _ => observation.jobs.first(),
        };

        let Some(job) = selected else {
            return ScriptedDecision::wait();
        };

        match self {
            Self::AlwaysPass | Self::TrivialJobsOnly | Self::MaximumVolume => {
                ScriptedDecision::validate(job, |_| Verdict::Pass)
            }
            Self::AlwaysFail => ScriptedDecision::validate(job, |_| Verdict::Fail),
            Self::RandomVerdict { seed } => ScriptedDecision::validate(job, |claim| {
                random_verdict(seed, observation.epoch, observation.height, job, claim)
            }),
            Self::ConsensusFollower => {
                ScriptedDecision::validate(job, |claim| claim.revealed_peer_verdicts.majority())
            }
            Self::PerfectAbstainer => ScriptedDecision::abstain(job.job_id),
            Self::HistoricalMajorityFollower => {
                let verdict = observation.public_history.majority();
                ScriptedDecision::validate(job, |_| verdict)
            }
        }
    }
}

/// Remaining host resources visible at a scripted decision point.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyResourceBudget {
    pub remaining_model_calls: u64,
    pub remaining_tool_calls: u64,
    pub remaining_validation_seconds: u64,
}

/// Resources consumed by a scripted policy decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyResourceReport {
    pub model_calls: u64,
    pub tool_calls: u64,
}

impl PolicyResourceReport {
    /// Scripted controls invoke neither models nor tools.
    pub const NONE: Self = Self {
        model_calls: 0,
        tool_calls: 0,
    };

    /// Returns whether this report stays within the observable hard budget.
    pub const fn fits_within(self, budget: PolicyResourceBudget) -> bool {
        self.model_calls <= budget.remaining_model_calls
            && self.tool_calls <= budget.remaining_tool_calls
    }
}

/// Counts of public verdicts. Ties and an empty tally yield `Indeterminate`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerdictTally {
    pub pass: u64,
    pub fail: u64,
    pub abstain: u64,
    pub indeterminate: u64,
}

impl VerdictTally {
    /// Returns the unique most frequent verdict, or `Indeterminate` when there
    /// is no public verdict or the highest count is tied.
    pub fn majority(self) -> Verdict {
        let counts = [
            (self.pass, Verdict::Pass),
            (self.fail, Verdict::Fail),
            (self.abstain, Verdict::Abstain),
            (self.indeterminate, Verdict::Indeterminate),
        ];
        let maximum = counts.iter().map(|(count, _)| *count).max().unwrap_or(0);
        if maximum == 0 || counts.iter().filter(|(count, _)| *count == maximum).count() != 1 {
            return Verdict::Indeterminate;
        }

        counts
            .into_iter()
            .find_map(|(count, verdict)| (count == maximum).then_some(verdict))
            .unwrap_or(Verdict::Indeterminate)
    }
}

/// One public claim available to a scripted operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedClaim {
    claim_id: ClaimId,
    /// Only already revealed peer verdicts may be summarized here.
    revealed_peer_verdicts: VerdictTally,
}

impl ObservedClaim {
    pub const fn new(claim_id: ClaimId, revealed_peer_verdicts: VerdictTally) -> Self {
        Self {
            claim_id,
            revealed_peer_verdicts,
        }
    }

    pub const fn claim_id(&self) -> ClaimId {
        self.claim_id
    }

    pub const fn revealed_peer_verdicts(&self) -> VerdictTally {
        self.revealed_peer_verdicts
    }
}

/// One public job available to a scripted operator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedJob {
    job_id: JobId,
    claims: Vec<ObservedClaim>,
    /// A predeclared public control label, never evaluator difficulty or truth.
    publicly_trivial: bool,
}

impl ObservedJob {
    pub fn new(
        job_id: JobId,
        claims: Vec<ObservedClaim>,
        publicly_trivial: bool,
    ) -> Result<Self, PolicyInputError> {
        if claims.is_empty() {
            return Err(PolicyInputError::JobHasNoClaims);
        }
        if claims.len() > MAX_CLAIMS_PER_JOB {
            return Err(PolicyInputError::TooManyClaims {
                count: claims.len(),
                maximum: MAX_CLAIMS_PER_JOB,
            });
        }
        let mut claim_ids = BTreeSet::new();
        if claims.iter().any(|claim| !claim_ids.insert(claim.claim_id)) {
            return Err(PolicyInputError::DuplicateClaim);
        }

        Ok(Self {
            job_id,
            claims,
            publicly_trivial,
        })
    }

    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    pub fn claims(&self) -> &[ObservedClaim] {
        &self.claims
    }

    pub const fn is_publicly_trivial(&self) -> bool {
        self.publicly_trivial
    }
}

/// Complete public input to one pure policy decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyObservation {
    epoch: u64,
    height: u64,
    resource_budget: PolicyResourceBudget,
    jobs: Vec<ObservedJob>,
    /// Aggregate of previously revealed public operator verdicts only.
    public_history: VerdictTally,
}

impl PolicyObservation {
    pub fn new(
        epoch: u64,
        height: u64,
        resource_budget: PolicyResourceBudget,
        jobs: Vec<ObservedJob>,
        public_history: VerdictTally,
    ) -> Result<Self, PolicyInputError> {
        if jobs.len() > MAX_AVAILABLE_JOBS {
            return Err(PolicyInputError::TooManyJobs {
                count: jobs.len(),
                maximum: MAX_AVAILABLE_JOBS,
            });
        }
        let mut job_ids = BTreeSet::new();
        if jobs.iter().any(|job| !job_ids.insert(job.job_id)) {
            return Err(PolicyInputError::DuplicateJob);
        }

        Ok(Self {
            epoch,
            height,
            resource_budget,
            jobs,
            public_history,
        })
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn height(&self) -> u64 {
        self.height
    }

    pub const fn resource_budget(&self) -> PolicyResourceBudget {
        self.resource_budget
    }

    pub fn jobs(&self) -> &[ObservedJob] {
        &self.jobs
    }

    pub const fn public_history(&self) -> VerdictTally {
        self.public_history
    }
}

/// One claim verdict emitted by a scripted policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptedClaimDecision {
    pub claim_id: ClaimId,
    pub verdict: Verdict,
    /// Scripted controls make no evidence-based confidence claim.
    pub confidence_basis_points: u16,
}

/// The policy-level decision shape consumed by the deterministic lab runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScriptedDecisionKind {
    Validate {
        job_id: JobId,
        claims: Vec<ScriptedClaimDecision>,
    },
    Abstain {
        job_id: JobId,
    },
    Wait,
}

/// A pure decision plus its auditable zero-cost model/tool report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptedDecision {
    pub kind: ScriptedDecisionKind,
    pub resource_report: PolicyResourceReport,
}

impl ScriptedDecision {
    fn validate(job: &ObservedJob, mut verdict: impl FnMut(&ObservedClaim) -> Verdict) -> Self {
        let claims = job
            .claims
            .iter()
            .map(|claim| ScriptedClaimDecision {
                claim_id: claim.claim_id,
                verdict: verdict(claim),
                confidence_basis_points: 0,
            })
            .collect();
        Self {
            kind: ScriptedDecisionKind::Validate {
                job_id: job.job_id,
                claims,
            },
            resource_report: PolicyResourceReport::NONE,
        }
    }

    const fn abstain(job_id: JobId) -> Self {
        Self {
            kind: ScriptedDecisionKind::Abstain { job_id },
            resource_report: PolicyResourceReport::NONE,
        }
    }

    const fn wait() -> Self {
        Self {
            kind: ScriptedDecisionKind::Wait,
            resource_report: PolicyResourceReport::NONE,
        }
    }
}

/// Rejected unbounded or ambiguous policy input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyInputError {
    TooManyJobs { count: usize, maximum: usize },
    JobHasNoClaims,
    TooManyClaims { count: usize, maximum: usize },
    DuplicateJob,
    DuplicateClaim,
}

impl fmt::Display for PolicyInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyJobs { count, maximum } => {
                write!(
                    formatter,
                    "observation has {count} jobs; maximum is {maximum}"
                )
            }
            Self::JobHasNoClaims => formatter.write_str("observed job has no claims"),
            Self::TooManyClaims { count, maximum } => {
                write!(
                    formatter,
                    "observed job has {count} claims; maximum is {maximum}"
                )
            }
            Self::DuplicateJob => formatter.write_str("observation contains a duplicate job"),
            Self::DuplicateClaim => formatter.write_str("observed job contains a duplicate claim"),
        }
    }
}

impl Error for PolicyInputError {}

fn largest_job(jobs: &[ObservedJob]) -> Option<&ObservedJob> {
    let mut selected = jobs.first()?;
    for job in &jobs[1..] {
        if job.claims.len() > selected.claims.len() {
            selected = job;
        }
    }
    Some(selected)
}

fn random_verdict(
    seed: u64,
    epoch: u64,
    height: u64,
    job: &ObservedJob,
    claim: &ObservedClaim,
) -> Verdict {
    let mut state = seed ^ 0x7261_6368_6574_7631;
    mix(&mut state, &epoch.to_be_bytes());
    mix(&mut state, &height.to_be_bytes());
    mix(&mut state, job.job_id.as_bytes());
    mix(&mut state, claim.claim_id.as_bytes());
    if splitmix64(state).is_multiple_of(2) {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

fn mix(state: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *state ^= u64::from(*byte);
        *state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(index: u64, tally: VerdictTally) -> ObservedClaim {
        ObservedClaim::new(ClaimId::derive(&index.to_be_bytes()), tally)
    }

    fn job(index: u64, claim_count: u64, trivial: bool) -> ObservedJob {
        ObservedJob::new(
            JobId::derive(&index.to_be_bytes()),
            (0..claim_count)
                .map(|claim_index| claim(index * 1_000 + claim_index, VerdictTally::default()))
                .collect(),
            trivial,
        )
        .unwrap()
    }

    fn observation(jobs: Vec<ObservedJob>, history: VerdictTally) -> PolicyObservation {
        PolicyObservation::new(
            7,
            42,
            PolicyResourceBudget {
                remaining_model_calls: 0,
                remaining_tool_calls: 0,
                remaining_validation_seconds: 0,
            },
            jobs,
            history,
        )
        .unwrap()
    }

    fn verdicts(decision: &ScriptedDecision) -> Vec<Verdict> {
        match &decision.kind {
            ScriptedDecisionKind::Validate { claims, .. } => {
                claims.iter().map(|claim| claim.verdict).collect()
            }
            ScriptedDecisionKind::Abstain { .. } | ScriptedDecisionKind::Wait => Vec::new(),
        }
    }

    #[test]
    fn every_policy_is_explicitly_a_non_resource_matched_trivial_heuristic() {
        for policy in [
            ScriptedPolicy::AlwaysPass,
            ScriptedPolicy::AlwaysFail,
            ScriptedPolicy::RandomVerdict { seed: 1 },
            ScriptedPolicy::TrivialJobsOnly,
            ScriptedPolicy::ConsensusFollower,
            ScriptedPolicy::MaximumVolume,
            ScriptedPolicy::PerfectAbstainer,
            ScriptedPolicy::HistoricalMajorityFollower,
        ] {
            let metadata = policy.metadata();
            assert_eq!(
                metadata.classification(),
                PolicyClassification::TrivialHeuristic
            );
            assert!(!metadata.is_resource_matched_intelligent_baseline());
            assert!(!metadata.id().is_empty());
        }
    }

    #[test]
    fn always_policies_emit_exact_canonical_verdicts() {
        let observation = observation(vec![job(1, 3, false)], VerdictTally::default());
        assert_eq!(
            verdicts(&ScriptedPolicy::AlwaysPass.decide(&observation)),
            vec![Verdict::Pass; 3]
        );
        assert_eq!(
            verdicts(&ScriptedPolicy::AlwaysFail.decide(&observation)),
            vec![Verdict::Fail; 3]
        );
    }

    #[test]
    fn explicit_seed_random_policy_replays_exactly() {
        let observation = observation(vec![job(1, 64, false)], VerdictTally::default());
        let first = ScriptedPolicy::RandomVerdict { seed: 91 }.decide(&observation);
        let replay = ScriptedPolicy::RandomVerdict { seed: 91 }.decide(&observation);
        let other_seed = ScriptedPolicy::RandomVerdict { seed: 92 }.decide(&observation);

        assert_eq!(first, replay);
        assert_ne!(verdicts(&first), verdicts(&other_seed));
        assert!(
            verdicts(&first)
                .iter()
                .all(|verdict| matches!(verdict, Verdict::Pass | Verdict::Fail))
        );
    }

    #[test]
    fn trivial_policy_uses_only_the_public_trivial_label() {
        let ordinary = job(1, 2, false);
        let trivial = job(2, 1, true);
        let with_trivial = observation(vec![ordinary, trivial.clone()], VerdictTally::default());
        let decision = ScriptedPolicy::TrivialJobsOnly.decide(&with_trivial);
        assert!(matches!(
            decision.kind,
            ScriptedDecisionKind::Validate { job_id, .. } if job_id == trivial.job_id()
        ));

        let no_trivial = observation(vec![job(3, 1, false)], VerdictTally::default());
        assert_eq!(
            ScriptedPolicy::TrivialJobsOnly.decide(&no_trivial).kind,
            ScriptedDecisionKind::Wait
        );
    }

    #[test]
    fn consensus_follower_uses_only_current_revealed_operator_majorities() {
        let claims = vec![
            claim(
                1,
                VerdictTally {
                    pass: 3,
                    fail: 1,
                    ..VerdictTally::default()
                },
            ),
            claim(
                2,
                VerdictTally {
                    pass: 2,
                    fail: 4,
                    ..VerdictTally::default()
                },
            ),
            claim(
                3,
                VerdictTally {
                    pass: 2,
                    fail: 2,
                    ..VerdictTally::default()
                },
            ),
        ];
        let observed_job = ObservedJob::new(JobId::derive(b"majority"), claims, false).unwrap();
        let observation = observation(vec![observed_job], VerdictTally::default());

        assert_eq!(
            verdicts(&ScriptedPolicy::ConsensusFollower.decide(&observation)),
            vec![Verdict::Pass, Verdict::Fail, Verdict::Indeterminate]
        );
    }

    #[test]
    fn maximum_volume_selects_the_first_largest_job_and_all_its_claims() {
        let small = job(1, 1, false);
        let first_large = job(2, 4, false);
        let second_large = job(3, 4, false);
        let observation = observation(
            vec![small, first_large.clone(), second_large],
            VerdictTally::default(),
        );
        let decision = ScriptedPolicy::MaximumVolume.decide(&observation);

        match decision.kind {
            ScriptedDecisionKind::Validate { job_id, claims } => {
                assert_eq!(job_id, first_large.job_id());
                assert_eq!(claims.len(), 4);
                assert!(claims.iter().all(|claim| claim.verdict == Verdict::Pass));
            }
            other => panic!("unexpected maximum-volume decision: {other:?}"),
        }
    }

    #[test]
    fn perfect_abstainer_abstains_when_work_exists_and_waits_otherwise() {
        let available = observation(vec![job(9, 1, false)], VerdictTally::default());
        assert!(matches!(
            ScriptedPolicy::PerfectAbstainer.decide(&available).kind,
            ScriptedDecisionKind::Abstain { .. }
        ));
        assert_eq!(
            ScriptedPolicy::PerfectAbstainer
                .decide(&observation(Vec::new(), VerdictTally::default()))
                .kind,
            ScriptedDecisionKind::Wait
        );
    }

    #[test]
    fn historical_follower_uses_public_history_and_treats_ties_as_indeterminate() {
        let fail_history = observation(
            vec![job(1, 2, false)],
            VerdictTally {
                pass: 8,
                fail: 13,
                ..VerdictTally::default()
            },
        );
        assert_eq!(
            verdicts(&ScriptedPolicy::HistoricalMajorityFollower.decide(&fail_history)),
            vec![Verdict::Fail; 2]
        );

        let tied_history = observation(
            vec![job(1, 1, false)],
            VerdictTally {
                pass: 5,
                fail: 5,
                ..VerdictTally::default()
            },
        );
        assert_eq!(
            verdicts(&ScriptedPolicy::HistoricalMajorityFollower.decide(&tied_history)),
            vec![Verdict::Indeterminate]
        );
    }

    #[test]
    fn every_policy_is_deterministic_and_reports_usage_within_zero_budgets() {
        let observation = observation(vec![job(1, 2, true)], VerdictTally::default());
        for policy in [
            ScriptedPolicy::AlwaysPass,
            ScriptedPolicy::AlwaysFail,
            ScriptedPolicy::RandomVerdict { seed: 123 },
            ScriptedPolicy::TrivialJobsOnly,
            ScriptedPolicy::ConsensusFollower,
            ScriptedPolicy::MaximumVolume,
            ScriptedPolicy::PerfectAbstainer,
            ScriptedPolicy::HistoricalMajorityFollower,
        ] {
            let first = policy.decide(&observation);
            assert_eq!(first, policy.decide(&observation));
            assert!(
                first
                    .resource_report
                    .fits_within(observation.resource_budget())
            );
        }
    }

    #[test]
    fn observations_reject_unbounded_and_duplicate_inputs() {
        let duplicate_claim = claim(1, VerdictTally::default());
        assert_eq!(
            ObservedJob::new(
                JobId::derive(b"duplicate-claim"),
                vec![duplicate_claim.clone(), duplicate_claim],
                false,
            ),
            Err(PolicyInputError::DuplicateClaim)
        );
        let duplicate_job = job(1, 1, false);
        assert_eq!(
            PolicyObservation::new(
                0,
                0,
                PolicyResourceBudget::default(),
                vec![duplicate_job.clone(), duplicate_job],
                VerdictTally::default(),
            ),
            Err(PolicyInputError::DuplicateJob)
        );
        assert_eq!(
            ObservedJob::new(JobId::derive(b"empty"), Vec::new(), false),
            Err(PolicyInputError::JobHasNoClaims)
        );
    }
}
