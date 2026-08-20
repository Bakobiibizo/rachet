//! Stable node-owned observability metrics layered over Commonware telemetry.
//!
//! The counters here cover Rachet boundaries while the live exporter appends the
//! real Commonware registry for Simplex views/timeouts, peer connectivity,
//! Stateful branches, and QMDB commit histograms. Metrics never feed canonical
//! execution.

use crate::{mempool::PendingActionPool, persistence::FinalizedQueryIndex};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

/// Cloneable source for the live Commonware Prometheus registry.
#[derive(Clone)]
pub struct RuntimeMetricsExporter(Arc<dyn Fn() -> String + Send + Sync>);

impl RuntimeMetricsExporter {
    /// Captures a bounded callback that returns the current registry encoding.
    pub fn new(encode: impl Fn() -> String + Send + Sync + 'static) -> Self {
        Self(Arc::new(encode))
    }

    fn encode(&self) -> String {
        (self.0)()
    }

    /// Returns the number of currently connected Commonware peers.
    pub fn connected_peers(&self) -> u64 {
        metric_sample_count(&self.encode(), "_connected{")
    }
}

impl Default for RuntimeMetricsExporter {
    fn default() -> Self {
        Self::new(String::new)
    }
}

/// Integer-only counters for node-owned ingress, application, resolver, and RPC boundaries.
#[derive(Default)]
pub struct NodeMetrics {
    actions_accepted: AtomicU64,
    actions_rejected: AtomicU64,
    blocks_proposed: AtomicU64,
    blocks_verified: AtomicU64,
    blocks_rejected: AtomicU64,
    resolver_requests: AtomicU64,
    rpc_requests: AtomicU64,
    rpc_latency_microseconds_total: AtomicU64,
    rpc_latency_microseconds_last: AtomicU64,
    rpc_latency_microseconds_max: AtomicU64,
}

impl NodeMetrics {
    /// Records one action reaching the shared bounded admission boundary.
    pub fn observe_action(&self, accepted: bool) {
        if accepted {
            self.actions_accepted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.actions_rejected.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records one successfully constructed local proposal.
    pub fn observe_block_proposed(&self) {
        self.blocks_proposed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one completed consensus verification verdict.
    pub fn observe_block_verification(&self, accepted: bool) {
        if accepted {
            self.blocks_verified.fetch_add(1, Ordering::Relaxed);
        } else {
            self.blocks_rejected.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records one state-sync request dispatched to authenticated peers.
    pub fn observe_resolver_request(&self) {
        self.resolver_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one completed HTTP request using monotonic elapsed time only.
    pub fn observe_rpc(&self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.rpc_requests.fetch_add(1, Ordering::Relaxed);
        self.rpc_latency_microseconds_total
            .fetch_add(micros, Ordering::Relaxed);
        self.rpc_latency_microseconds_last
            .store(micros, Ordering::Relaxed);
        self.rpc_latency_microseconds_max
            .fetch_max(micros, Ordering::Relaxed);
    }

    /// Encodes stable Rachet metrics and appends the live Commonware registry.
    pub fn encode(
        &self,
        pool: &PendingActionPool,
        finalized: &FinalizedQueryIndex,
        runtime: &RuntimeMetricsExporter,
    ) -> String {
        let snapshot = finalized.snapshot();
        let commonware = runtime.encode();
        let mut output = String::with_capacity(4_096);
        metric(
            &mut output,
            "rachet_finalized_height",
            snapshot.finalized_height,
        );
        metric(&mut output, "rachet_current_epoch", snapshot.current_epoch);
        output.push_str("# TYPE rachet_finalized_state_root_info gauge\n");
        output.push_str("rachet_finalized_state_root_info{digest=\"");
        push_hex(&mut output, snapshot.finalized_state_root.as_ref());
        output.push_str("\"} 1\n");
        metric(
            &mut output,
            "rachet_pending_actions",
            usize_to_u64(pool.len()),
        );
        metric(
            &mut output,
            "rachet_pending_action_bytes",
            usize_to_u64(pool.total_bytes()),
        );
        metric(
            &mut output,
            "rachet_actions_accepted_total",
            self.actions_accepted.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_actions_rejected_total",
            self.actions_rejected.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_blocks_proposed_total",
            self.blocks_proposed.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_blocks_verified_total",
            self.blocks_verified.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_blocks_rejected_total",
            self.blocks_rejected.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_consensus_current_view",
            metric_max(&commonware, "_simplex_voter_state_current_view"),
        );
        metric(
            &mut output,
            "rachet_consensus_timeouts_total",
            metric_sum(&commonware, "_simplex_voter_state_timeouts"),
        );
        metric(
            &mut output,
            "rachet_connected_peers",
            metric_sample_count(&commonware, "_connected{"),
        );
        metric(
            &mut output,
            "rachet_resolver_requests_total",
            self.resolver_requests.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_stateful_pending_branches",
            metric_max(&commonware, "_stateful_pending_blocks"),
        );
        metric(
            &mut output,
            "rachet_qmdb_commit_duration_observations_total",
            metric_sum(&commonware, "_stateful_db_set_any_commit_duration_count"),
        );
        metric(
            &mut output,
            "rachet_finalization_latency_milliseconds",
            snapshot.last_finalization_latency_ms,
        );
        metric(
            &mut output,
            "rachet_rpc_requests_total",
            self.rpc_requests.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_rpc_latency_microseconds_total",
            self.rpc_latency_microseconds_total.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_rpc_latency_microseconds_last",
            self.rpc_latency_microseconds_last.load(Ordering::Relaxed),
        );
        metric(
            &mut output,
            "rachet_rpc_latency_microseconds_max",
            self.rpc_latency_microseconds_max.load(Ordering::Relaxed),
        );

        if !commonware.is_empty() {
            output.push_str("# Commonware release-path metrics: Simplex views/timeouts, peer connectivity, Stateful pending branches, and QMDB commit duration.\n");
            output.push_str(&commonware);
            if !commonware.ends_with('\n') {
                output.push('\n');
            }
        }
        output
    }
}

fn metric(output: &mut String, name: &str, value: u64) {
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push_str(" gauge\n");
    output.push_str(name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn metric_max(encoded: &str, name_fragment: &str) -> u64 {
    metric_values(encoded, name_fragment).max().unwrap_or(0)
}

fn metric_sum(encoded: &str, name_fragment: &str) -> u64 {
    metric_values(encoded, name_fragment).fold(0_u64, u64::saturating_add)
}

fn metric_values<'a>(encoded: &'a str, name_fragment: &'a str) -> impl Iterator<Item = u64> + 'a {
    encoded.lines().filter_map(move |line| {
        if line.starts_with('#') {
            return None;
        }
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next()?;
        let value = fields.next()?;
        (name.contains(name_fragment) && fields.next().is_none())
            .then(|| value.parse::<u64>().ok())
            .flatten()
    })
}

fn metric_sample_count(encoded: &str, name_fragment: &str) -> u64 {
    usize_to_u64(
        encoded
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split_ascii_whitespace().next())
            .filter(|name| name.contains(name_fragment))
            .count(),
    )
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}
