//! Strict `operator-decision.v1` parsing and canonical action signing.
//!
//! This boundary accepts JSON only. It never strips Markdown fences, searches
//! for an embedded object, fills missing fields, drops unknown fields, or
//! otherwise repairs agent output. Every attempt retains the exact raw bytes.

use crate::budget::{BudgetError, BudgetTracker, ResourceUsage};
use rachet_client::{
    identity::ActorIdentity,
    signing::{ActionSigningRequest, SigningError, sign_action},
};
use rachet_core::{
    actions::{Action, ChallengeTarget, CreateChallenge, SubmitAttestation, Verdict},
    bounded::{BoundedBytes, BoundedVec},
    limits::{MAX_COUNTERCLAIM_BYTES, MAX_EVIDENCE_IDS_PER_ACTION},
    primitives::{ChainId, ClaimId, EvidenceId, JobId},
};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, fmt};

pub const DECISION_SCHEMA_VERSION: &str = "operator-decision.v1";
/// Hard host-side input bound. The schema's maximum compact representation is
/// below this value; the remaining space permits ordinary JSON whitespace.
pub const MAX_DECISION_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

const MAX_IDENTIFIER_CHARS: usize = 128;
const MAX_REFERENCE_CHARS: usize = 2_048;
const MAX_CLAIMS: usize = 128;

/// One canonical claim advertised for an available job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableClaim {
    pub reference: String,
    pub claim_id: ClaimId,
}

/// One job the operator was permitted to act on at this decision point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableJob {
    pub reference: String,
    pub job_id: JobId,
    pub claims: Vec<AvailableClaim>,
}

/// One evidence reference the trusted host has resolved to registered evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableEvidence {
    pub reference: String,
    pub evidence_id: EvidenceId,
    pub job_id: JobId,
    /// `None` denotes job-wide evidence; claim-scoped evidence is usable only
    /// for that claim.
    pub claim_id: Option<ClaimId>,
}

/// Trusted signing and visibility context for one operator decision.
#[derive(Clone, Copy, Debug)]
pub struct DecisionContext<'a> {
    pub chain_id: ChainId,
    pub next_nonce: u64,
    pub valid_until_height: u64,
    pub available_jobs: &'a [AvailableJob],
    pub available_evidence: &'a [AvailableEvidence],
}

/// Resource counts declared by the strict wire contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionResourceReport {
    pub model_calls: u64,
    pub tool_calls: u64,
}

impl DecisionResourceReport {
    const fn usage(self) -> ResourceUsage {
        ResourceUsage {
            model_calls: self.model_calls,
            tool_calls: self.tool_calls,
            validation_seconds: 0,
        }
    }
}

/// A strictly parsed claim decision, before host references are resolved.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDecision {
    pub claim_id: String,
    pub verdict: DecisionVerdict,
    pub confidence_basis_points: u16,
    pub evidence_refs: Vec<String>,
}

/// Verdict names in `operator-decision.v1`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionVerdict {
    Pass,
    Fail,
    Abstain,
    Indeterminate,
}

impl From<DecisionVerdict> for Verdict {
    fn from(value: DecisionVerdict) -> Self {
        match value {
            DecisionVerdict::Pass => Self::Pass,
            DecisionVerdict::Fail => Self::Fail,
            DecisionVerdict::Abstain => Self::Abstain,
            DecisionVerdict::Indeterminate => Self::Indeterminate,
        }
    }
}

/// One schema-valid decision. References have not necessarily passed the
/// decision-point job and evidence rules yet.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedDecision {
    pub kind: ParsedDecisionKind,
    pub resource_report: DecisionResourceReport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ParsedDecisionKind {
    Validate {
        job_id: String,
        claims: Vec<ClaimDecision>,
    },
    Abstain {
        job_id: String,
    },
    Challenge {
        job_id: String,
        claims: Vec<ClaimDecision>,
    },
    Wait,
}

/// Exact raw output, parse result, and actions (or explicit failure) for one
/// invocation. Failure records always contain zero signed actions.
#[derive(Clone, Debug)]
pub struct DecisionRecord {
    raw_output: Vec<u8>,
    raw_output_sha256: String,
    pub parsed_decision: Option<ParsedDecision>,
    pub signed_actions: Vec<rachet_core::actions::SignedAction<Action>>,
    pub next_nonce: u64,
    pub failure: Option<OperatorFailure>,
}

impl DecisionRecord {
    pub fn raw_output(&self) -> &[u8] {
        &self.raw_output
    }

    pub fn raw_output_sha256(&self) -> &str {
        &self.raw_output_sha256
    }

    pub const fn succeeded(&self) -> bool {
        self.failure.is_none()
    }
}

/// Stable, machine-readable operator failure retained beside malformed output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorFailure {
    pub code: &'static str,
    pub message: String,
}

impl OperatorFailure {
    fn from_error(error: DecisionError) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}

/// Parses exact raw JSON, resolves only advertised jobs/evidence, enforces the
/// remaining budget, and signs all-or-nothing canonical actions.
///
/// The budget is charged only after the complete decision can be converted and
/// signed. A rejected charge is atomic. The returned `next_nonce` advances only
/// on success.
pub fn parse_and_sign(
    raw_output: Vec<u8>,
    context: DecisionContext<'_>,
    identity: &ActorIdentity,
    budget: &mut BudgetTracker,
) -> DecisionRecord {
    parse_and_sign_inner(raw_output, context, identity, budget, None)
}

/// Strict decision conversion for a completed external model process.
///
/// Unlike replay parsing, real process resources are consumed even when the
/// returned JSON or referenced action is invalid. At least one model call and
/// the measured wall time are therefore charged before an accepted decision is
/// exposed to deterministic execution.
pub(crate) fn parse_and_sign_metered(
    raw_output: Vec<u8>,
    context: DecisionContext<'_>,
    identity: &ActorIdentity,
    budget: &mut BudgetTracker,
    validation_seconds: u64,
) -> DecisionRecord {
    parse_and_sign_inner(
        raw_output,
        context,
        identity,
        budget,
        Some(validation_seconds),
    )
}

fn parse_and_sign_inner(
    raw_output: Vec<u8>,
    context: DecisionContext<'_>,
    identity: &ActorIdentity,
    budget: &mut BudgetTracker,
    external_validation_seconds: Option<u64>,
) -> DecisionRecord {
    let raw_output_sha256 = hash_hex(&raw_output);
    let mut record = DecisionRecord {
        raw_output,
        raw_output_sha256,
        parsed_decision: None,
        signed_actions: Vec::new(),
        next_nonce: context.next_nonce,
        failure: None,
    };

    let parsed = match parse(&record.raw_output) {
        Ok(parsed) => parsed,
        Err(error) => {
            if let Some(validation_seconds) = external_validation_seconds
                && let Err(budget_error) = budget.charge(ResourceUsage {
                    model_calls: 1,
                    tool_calls: 0,
                    validation_seconds,
                })
            {
                record.failure = Some(OperatorFailure::from_error(DecisionError::Budget(
                    budget_error,
                )));
                return record;
            }
            record.failure = Some(OperatorFailure::from_error(error));
            return record;
        }
    };
    record.parsed_decision = Some(parsed.clone());

    if let Some(validation_seconds) = external_validation_seconds {
        let usage = ResourceUsage {
            model_calls: parsed.resource_report.model_calls.max(1),
            tool_calls: parsed.resource_report.tool_calls,
            validation_seconds,
        };
        if let Err(error) = budget.charge(usage) {
            record.failure = Some(OperatorFailure::from_error(DecisionError::Budget(error)));
            return record;
        }
    }

    let payloads = match action_payloads(&parsed, &context) {
        Ok(payloads) => payloads,
        Err(error) => {
            record.failure = Some(OperatorFailure::from_error(error));
            return record;
        }
    };
    let (signed_actions, next_nonce) = match sign_payloads(payloads, context, identity) {
        Ok(signed) => signed,
        Err(error) => {
            record.failure = Some(OperatorFailure::from_error(error));
            return record;
        }
    };
    if external_validation_seconds.is_none()
        && let Err(error) = budget.charge(parsed.resource_report.usage())
    {
        record.failure = Some(OperatorFailure::from_error(DecisionError::Budget(error)));
        return record;
    }

    record.signed_actions = signed_actions;
    record.next_nonce = next_nonce;
    record
}

fn parse(raw_output: &[u8]) -> Result<ParsedDecision, DecisionError> {
    if raw_output.len() > MAX_DECISION_OUTPUT_BYTES {
        return Err(DecisionError::OutputTooLarge {
            bytes: raw_output.len(),
            maximum: MAX_DECISION_OUTPUT_BYTES,
        });
    }
    let wire: WireDecision =
        serde_json::from_slice(raw_output).map_err(|error| DecisionError::MalformedJson {
            message: error.to_string(),
        })?;
    if wire.schema_version != DECISION_SCHEMA_VERSION {
        return Err(DecisionError::SchemaViolation(
            "schema_version must be operator-decision.v1",
        ));
    }

    match wire.decision {
        WireDecisionName::Validate | WireDecisionName::Challenge => {
            let job_id = wire.job_id.present("job_id")?;
            let claims = wire.claims.present("claims")?;
            validate_identifier("job_id", &job_id)?;
            validate_claims(&claims)?;
            let kind = if wire.decision == WireDecisionName::Validate {
                ParsedDecisionKind::Validate { job_id, claims }
            } else {
                ParsedDecisionKind::Challenge { job_id, claims }
            };
            Ok(ParsedDecision {
                kind,
                resource_report: wire.resource_report,
            })
        }
        WireDecisionName::Abstain => {
            let job_id = wire.job_id.present("job_id")?;
            wire.claims.absent("claims")?;
            validate_identifier("job_id", &job_id)?;
            Ok(ParsedDecision {
                kind: ParsedDecisionKind::Abstain { job_id },
                resource_report: wire.resource_report,
            })
        }
        WireDecisionName::Wait => {
            wire.job_id.absent("job_id")?;
            wire.claims.absent("claims")?;
            Ok(ParsedDecision {
                kind: ParsedDecisionKind::Wait,
                resource_report: wire.resource_report,
            })
        }
    }
}

fn validate_claims(claims: &[ClaimDecision]) -> Result<(), DecisionError> {
    if claims.is_empty() || claims.len() > MAX_CLAIMS {
        return Err(DecisionError::SchemaViolation(
            "claims must contain between 1 and 128 items",
        ));
    }
    let mut claim_refs = BTreeSet::new();
    for claim in claims {
        validate_identifier("claim_id", &claim.claim_id)?;
        if claim.confidence_basis_points > 10_000 {
            return Err(DecisionError::SchemaViolation(
                "confidence_basis_points must not exceed 10000",
            ));
        }
        if !claim_refs.insert(claim.claim_id.as_str()) {
            return Err(DecisionError::DuplicateClaim);
        }
        if claim.evidence_refs.len() > MAX_EVIDENCE_IDS_PER_ACTION {
            return Err(DecisionError::SchemaViolation(
                "evidence_refs must not exceed 64 items",
            ));
        }
        let mut evidence_refs = BTreeSet::new();
        for reference in &claim.evidence_refs {
            validate_reference(reference)?;
            if !evidence_refs.insert(reference.as_str()) {
                return Err(DecisionError::DuplicateEvidence);
            }
        }
    }
    Ok(())
}

fn action_payloads(
    parsed: &ParsedDecision,
    context: &DecisionContext<'_>,
) -> Result<Vec<Action>, DecisionError> {
    match &parsed.kind {
        ParsedDecisionKind::Validate { job_id, claims } => {
            let job = resolve_job(job_id, context.available_jobs)?;
            claims
                .iter()
                .map(|claim| {
                    let claim_id = resolve_claim(&claim.claim_id, job)?;
                    Ok(Action::SubmitAttestation(SubmitAttestation {
                        job_id: job.job_id,
                        claim_id,
                        verdict: claim.verdict.into(),
                        confidence_basis_points: claim.confidence_basis_points,
                        evidence_ids: resolve_evidence(claim, job.job_id, claim_id, context)?,
                    }))
                })
                .collect()
        }
        ParsedDecisionKind::Abstain { job_id } => {
            let job = resolve_job(job_id, context.available_jobs)?;
            if job.claims.is_empty() {
                return Err(DecisionError::JobHasNoClaims);
            }
            ensure_unique_context_claims(job)?;
            Ok(job
                .claims
                .iter()
                .map(|claim| {
                    Action::SubmitAttestation(SubmitAttestation {
                        job_id: job.job_id,
                        claim_id: claim.claim_id,
                        verdict: Verdict::Abstain,
                        confidence_basis_points: 0,
                        evidence_ids: BoundedVec::default(),
                    })
                })
                .collect())
        }
        ParsedDecisionKind::Challenge { job_id, claims } => {
            let job = resolve_job(job_id, context.available_jobs)?;
            claims
                .iter()
                .map(|claim| {
                    let claim_id = resolve_claim(&claim.claim_id, job)?;
                    let counterclaim = ChallengeCounterclaim {
                        claim_id: &claim.claim_id,
                        verdict: claim.verdict,
                        confidence_basis_points: claim.confidence_basis_points,
                    };
                    let counterclaim = serde_json::to_vec(&counterclaim)
                        .map_err(|_| DecisionError::Serialization)?;
                    let counterclaim = BoundedBytes::<MAX_COUNTERCLAIM_BYTES>::new(counterclaim)
                        .map_err(|_| DecisionError::CounterclaimTooLarge)?;
                    Ok(Action::CreateChallenge(CreateChallenge {
                        target: ChallengeTarget::Claim(claim_id),
                        counterclaim,
                        evidence_ids: resolve_evidence(claim, job.job_id, claim_id, context)?,
                    }))
                })
                .collect()
        }
        ParsedDecisionKind::Wait => Ok(Vec::new()),
    }
}

fn resolve_job<'a>(
    reference: &str,
    available: &'a [AvailableJob],
) -> Result<&'a AvailableJob, DecisionError> {
    let mut matches = available.iter().filter(|job| job.reference == reference);
    let job = matches.next().ok_or(DecisionError::UnknownJob)?;
    if matches.next().is_some() {
        return Err(DecisionError::AmbiguousHostContext);
    }
    Ok(job)
}

fn resolve_claim(reference: &str, job: &AvailableJob) -> Result<ClaimId, DecisionError> {
    let mut matches = job
        .claims
        .iter()
        .filter(|claim| claim.reference == reference);
    let claim = matches.next().ok_or(DecisionError::UnknownClaim)?;
    if matches.next().is_some() {
        return Err(DecisionError::AmbiguousHostContext);
    }
    Ok(claim.claim_id)
}

fn ensure_unique_context_claims(job: &AvailableJob) -> Result<(), DecisionError> {
    let mut references = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for claim in &job.claims {
        if !references.insert(claim.reference.as_str()) || !ids.insert(claim.claim_id) {
            return Err(DecisionError::AmbiguousHostContext);
        }
    }
    Ok(())
}

fn resolve_evidence(
    claim: &ClaimDecision,
    job_id: JobId,
    claim_id: ClaimId,
    context: &DecisionContext<'_>,
) -> Result<BoundedVec<EvidenceId, MAX_EVIDENCE_IDS_PER_ACTION>, DecisionError> {
    let mut resolved = Vec::with_capacity(claim.evidence_refs.len());
    let mut ids = BTreeSet::new();
    for reference in &claim.evidence_refs {
        let mut matches = context
            .available_evidence
            .iter()
            .filter(|evidence| evidence.reference.as_str() == reference);
        let evidence = matches.next().ok_or(DecisionError::UnknownEvidence)?;
        if matches.next().is_some() {
            return Err(DecisionError::AmbiguousHostContext);
        }
        if evidence.job_id != job_id {
            return Err(DecisionError::EvidenceJobMismatch);
        }
        if evidence
            .claim_id
            .is_some_and(|evidence_claim| evidence_claim != claim_id)
        {
            return Err(DecisionError::EvidenceClaimMismatch);
        }
        if !ids.insert(evidence.evidence_id) {
            return Err(DecisionError::DuplicateEvidence);
        }
        resolved.push(evidence.evidence_id);
    }
    BoundedVec::new(resolved).map_err(|_| DecisionError::TooManyEvidence)
}

fn sign_payloads(
    payloads: Vec<Action>,
    context: DecisionContext<'_>,
    identity: &ActorIdentity,
) -> Result<(Vec<rachet_core::actions::SignedAction<Action>>, u64), DecisionError> {
    let count = u64::try_from(payloads.len()).map_err(|_| DecisionError::NonceExhausted)?;
    let next_nonce = context
        .next_nonce
        .checked_add(count)
        .ok_or(DecisionError::NonceExhausted)?;
    let mut signed = Vec::with_capacity(payloads.len());
    for (offset, payload) in payloads.into_iter().enumerate() {
        let offset = u64::try_from(offset).map_err(|_| DecisionError::NonceExhausted)?;
        let nonce = context
            .next_nonce
            .checked_add(offset)
            .ok_or(DecisionError::NonceExhausted)?;
        signed.push(
            sign_action(
                identity,
                ActionSigningRequest::current(
                    context.chain_id,
                    nonce,
                    context.valid_until_height,
                    payload,
                ),
            )
            .map_err(DecisionError::Signing)?,
        );
    }
    Ok((signed, next_nonce))
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), DecisionError> {
    let chars = value.chars().count();
    if chars == 0 || chars > MAX_IDENTIFIER_CHARS || value.chars().any(char::is_whitespace) {
        return Err(DecisionError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_reference(value: &str) -> Result<(), DecisionError> {
    let chars = value.chars().count();
    if chars == 0
        || chars > MAX_REFERENCE_CHARS
        || value.chars().any(|character| character <= '\u{001f}')
    {
        return Err(DecisionError::InvalidEvidenceReference);
    }
    Ok(())
}

fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WireDecisionName {
    Validate,
    Abstain,
    Challenge,
    Wait,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDecision {
    schema_version: String,
    decision: WireDecisionName,
    #[serde(default, deserialize_with = "present")]
    job_id: Field<String>,
    #[serde(default, deserialize_with = "present")]
    claims: Field<Vec<ClaimDecision>>,
    resource_report: DecisionResourceReport,
}

#[derive(Debug, Default)]
enum Field<T> {
    #[default]
    Missing,
    Present(T),
}

impl<T> Field<T> {
    fn present(self, name: &'static str) -> Result<T, DecisionError> {
        match self {
            Self::Present(value) => Ok(value),
            Self::Missing => Err(DecisionError::MissingField(name)),
        }
    }

    fn absent(self, name: &'static str) -> Result<(), DecisionError> {
        match self {
            Self::Missing => Ok(()),
            Self::Present(_) => Err(DecisionError::ForbiddenField(name)),
        }
    }
}

fn present<'de, D, T>(deserializer: D) -> Result<Field<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    T::deserialize(deserializer).map(Field::Present)
}

#[derive(Serialize)]
struct ChallengeCounterclaim<'a> {
    claim_id: &'a str,
    verdict: DecisionVerdict,
    confidence_basis_points: u16,
}

/// Stable rejection reasons at the strict decision boundary.
#[derive(Debug)]
enum DecisionError {
    OutputTooLarge { bytes: usize, maximum: usize },
    MalformedJson { message: String },
    SchemaViolation(&'static str),
    MissingField(&'static str),
    ForbiddenField(&'static str),
    InvalidIdentifier { field: &'static str },
    InvalidEvidenceReference,
    DuplicateClaim,
    DuplicateEvidence,
    UnknownJob,
    JobHasNoClaims,
    UnknownClaim,
    UnknownEvidence,
    EvidenceJobMismatch,
    EvidenceClaimMismatch,
    AmbiguousHostContext,
    TooManyEvidence,
    CounterclaimTooLarge,
    NonceExhausted,
    Serialization,
    Budget(BudgetError),
    Signing(SigningError),
}

impl DecisionError {
    const fn code(&self) -> &'static str {
        match self {
            Self::OutputTooLarge { .. } => "OPERATOR_DECISION_OUTPUT_TOO_LARGE",
            Self::MalformedJson { .. } => "OPERATOR_DECISION_MALFORMED_JSON",
            Self::SchemaViolation(_) | Self::MissingField(_) | Self::ForbiddenField(_) => {
                "OPERATOR_DECISION_SCHEMA_INVALID"
            }
            Self::InvalidIdentifier { .. } => "OPERATOR_DECISION_IDENTIFIER_INVALID",
            Self::InvalidEvidenceReference => "OPERATOR_DECISION_EVIDENCE_REF_INVALID",
            Self::DuplicateClaim => "OPERATOR_DECISION_CLAIM_DUPLICATE",
            Self::DuplicateEvidence => "OPERATOR_DECISION_EVIDENCE_DUPLICATE",
            Self::UnknownJob => "OPERATOR_DECISION_JOB_UNAVAILABLE",
            Self::JobHasNoClaims => "OPERATOR_DECISION_JOB_EMPTY",
            Self::UnknownClaim => "OPERATOR_DECISION_CLAIM_UNAVAILABLE",
            Self::UnknownEvidence => "OPERATOR_DECISION_EVIDENCE_UNAVAILABLE",
            Self::EvidenceJobMismatch => "OPERATOR_DECISION_EVIDENCE_JOB_MISMATCH",
            Self::EvidenceClaimMismatch => "OPERATOR_DECISION_EVIDENCE_CLAIM_MISMATCH",
            Self::AmbiguousHostContext => "OPERATOR_DECISION_HOST_CONTEXT_AMBIGUOUS",
            Self::TooManyEvidence => "OPERATOR_DECISION_EVIDENCE_LIMIT",
            Self::CounterclaimTooLarge => "OPERATOR_DECISION_COUNTERCLAIM_TOO_LARGE",
            Self::NonceExhausted => "OPERATOR_DECISION_NONCE_EXHAUSTED",
            Self::Serialization => "OPERATOR_DECISION_SERIALIZATION_FAILED",
            Self::Budget(error) => error.code(),
            Self::Signing(error) => error.code(),
        }
    }
}

impl fmt::Display for DecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLarge { bytes, maximum } => {
                write!(
                    formatter,
                    "operator decision is {bytes} bytes; maximum is {maximum}"
                )
            }
            Self::MalformedJson { message } => {
                write!(formatter, "malformed strict JSON: {message}")
            }
            Self::SchemaViolation(message) => {
                write!(formatter, "decision schema violation: {message}")
            }
            Self::MissingField(field) => write!(formatter, "decision requires field {field}"),
            Self::ForbiddenField(field) => write!(formatter, "decision forbids field {field}"),
            Self::InvalidIdentifier { field } => write!(formatter, "invalid decision {field}"),
            Self::InvalidEvidenceReference => {
                formatter.write_str("invalid decision evidence reference")
            }
            Self::DuplicateClaim => formatter.write_str("decision repeats a claim"),
            Self::DuplicateEvidence => formatter.write_str("decision repeats evidence"),
            Self::UnknownJob => formatter.write_str("decision job was not advertised as available"),
            Self::JobHasNoClaims => formatter.write_str("decision job has no advertised claims"),
            Self::UnknownClaim => {
                formatter.write_str("decision claim does not belong to the available job")
            }
            Self::UnknownEvidence => {
                formatter.write_str("decision evidence was not made available")
            }
            Self::EvidenceJobMismatch => {
                formatter.write_str("decision evidence belongs to another job")
            }
            Self::EvidenceClaimMismatch => {
                formatter.write_str("decision evidence belongs to another claim")
            }
            Self::AmbiguousHostContext => {
                formatter.write_str("trusted host context contains ambiguous references")
            }
            Self::TooManyEvidence => {
                formatter.write_str("decision exceeds the canonical evidence limit")
            }
            Self::CounterclaimTooLarge => {
                formatter.write_str("challenge counterclaim exceeds the canonical byte limit")
            }
            Self::NonceExhausted => formatter.write_str("operator action nonce is exhausted"),
            Self::Serialization => {
                formatter.write_str("cannot serialize canonical challenge counterclaim")
            }
            Self::Budget(error) => error.fmt(formatter),
            Self::Signing(error) => error.fmt(formatter),
        }
    }
}
