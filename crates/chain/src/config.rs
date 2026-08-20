//! Bounded, immutable startup configuration for one live consensus node.
//!
//! JSON is a node-operator format only. Validation converts it into the typed
//! genesis and runtime configuration before Commonware opens storage or starts
//! any actor.

use crate::{
    application::{GenesisMetadata, GenesisState},
    engine::{
        CommitteeNetworkGenesis, CommitteePeer, ConsensusNodeKey, FIXED_COMMITTEE_SIZE,
        LiveNodeConfig,
    },
    mempool::PendingPoolLimits,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::{
    blocks::ConsensusNodeId,
    limits::{MAX_ACTION_BYTES, ProtocolLimits},
    mechanisms::{
        CanonicalMechanismConfig, GenesisConfig, GenesisProtocolConfig, MechanismId,
        MechanismSelection, MechanismVersion,
    },
    primitives::{ActorId, ChainId},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fmt, net::SocketAddr, path::PathBuf};

/// Maximum accepted node-configuration document size.
pub const MAX_NODE_CONFIG_BYTES: usize = 256 * 1024;
const MAX_NODE_NAME_BYTES: usize = 128;
const MAX_STORAGE_PATH_BYTES: usize = 4_096;
const MAX_STORAGE_PREFIX_BYTES: usize = 128;
const MAX_PENDING_ACTIONS: usize = 1_000_000;
const MAX_PENDING_BYTES: usize = 1024 * 1024 * 1024;
const MAX_NONCE_GAP: u64 = 1_000_000;
const SCHEMA_VERSION: u16 = 1;

/// Stable development-genesis timestamp used by `rcht-node init`.
pub const DEVNET_GENESIS_TIMESTAMP_MS: u64 = 1_725_000_000_123;
const DEVNET_CONSENSUS_SEED: u64 = 0x5243_4854_4e4f_4400;
const DEVNET_AUTHORITY_SEED: u64 = 0x5243_4854_4155_5448;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    schema_version: u16,
    node: NodeSection,
    committee: Vec<CommitteeEntry>,
    genesis: GenesisSection,
    storage: StorageSection,
    rpc: RpcSection,
    pending_pool: PendingPoolSection,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeSection {
    name: String,
    index: usize,
    consensus_private_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitteeEntry {
    consensus_public_key: String,
    address: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisSection {
    chain_id: String,
    timestamp_ms: u64,
    metadata_hex: String,
    mechanisms: Vec<MechanismEntry>,
    resolution_authorities: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MechanismEntry {
    id: String,
    version: String,
    config_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StorageSection {
    directory: String,
    prefix: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RpcSection {
    listen: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingPoolSection {
    max_actions: usize,
    max_actions_per_actor: usize,
    max_total_bytes: usize,
    max_nonce_gap: u64,
}

impl NodeConfig {
    /// Parses a bounded JSON document without consulting process state.
    pub fn parse(bytes: &[u8]) -> Result<Self, NodeConfigError> {
        if bytes.len() > MAX_NODE_CONFIG_BYTES {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_TOO_LARGE",
                format!(
                    "node configuration is {} bytes; maximum is {MAX_NODE_CONFIG_BYTES}",
                    bytes.len()
                ),
            ));
        }
        serde_json::from_slice(bytes).map_err(|error| {
            NodeConfigError::new(
                "NODE_CONFIG_PARSE_FAILED",
                format!("cannot parse node configuration JSON: {error}"),
            )
        })
    }

    /// Creates one interoperable local-development member of the fixed committee.
    ///
    /// The generated keys are deterministic development keys and MUST NOT be used
    /// for a public or security-sensitive deployment.
    pub fn devnet(node_index: usize, storage_directory: PathBuf) -> Result<Self, NodeConfigError> {
        if node_index >= FIXED_COMMITTEE_SIZE {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_NODE_INDEX_INVALID",
                format!(
                    "node index {node_index} is outside fixed committee 0..{}",
                    FIXED_COMMITTEE_SIZE - 1
                ),
            ));
        }
        let keys = (0..FIXED_COMMITTEE_SIZE)
            .map(|index| ed25519::PrivateKey::from_seed(DEVNET_CONSENSUS_SEED + index as u64))
            .collect::<Vec<_>>();
        let authority = ed25519::PrivateKey::from_seed(DEVNET_AUTHORITY_SEED).public_key();
        let config = Self {
            schema_version: SCHEMA_VERSION,
            node: NodeSection {
                name: format!("devnet-node-{node_index}"),
                index: node_index,
                consensus_private_key: encode_hex(keys[node_index].encode().as_ref()),
            },
            committee: keys
                .iter()
                .enumerate()
                .map(|(index, key)| CommitteeEntry {
                    consensus_public_key: encode_hex(key.public_key().encode().as_ref()),
                    address: format!("127.0.0.1:{}", 31_000 + index),
                })
                .collect(),
            genesis: GenesisSection {
                chain_id: encode_hex(&[0x52; 32]),
                timestamp_ms: DEVNET_GENESIS_TIMESTAMP_MS,
                metadata_hex: encode_hex(b"rachet core v1 devnet"),
                mechanisms: vec![MechanismEntry {
                    id: "M00".to_owned(),
                    version: "1.0.0".to_owned(),
                    config_hex: String::new(),
                }],
                resolution_authorities: vec![encode_hex(authority.encode().as_ref())],
            },
            storage: StorageSection {
                directory: storage_directory.to_string_lossy().into_owned(),
                prefix: format!("rachet-devnet-node-{node_index}"),
            },
            rpc: RpcSection {
                listen: format!("127.0.0.1:{}", 32_000 + node_index),
            },
            pending_pool: PendingPoolSection {
                max_actions: 1_024,
                max_actions_per_actor: 64,
                max_total_bytes: 16 * 1024 * 1024,
                max_nonce_gap: 32,
            },
        };
        // Keep init and run on exactly the same validation path.
        config.clone().validate()?;
        Ok(config)
    }

    /// Validates every bounded field and constructs the one-shot live-node input.
    pub fn validate(self) -> Result<ValidatedNodeConfig, NodeConfigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_SCHEMA_UNSUPPORTED",
                format!(
                    "node configuration schema {} is unsupported",
                    self.schema_version
                ),
            ));
        }
        validate_identifier(&self.node.name, MAX_NODE_NAME_BYTES, "node name")?;
        if self.node.index >= FIXED_COMMITTEE_SIZE {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_NODE_INDEX_INVALID",
                format!(
                    "node index {} is outside the fixed committee",
                    self.node.index
                ),
            ));
        }

        let private_key = decode_private_key(&self.node.consensus_private_key)?;
        if self.committee.len() != FIXED_COMMITTEE_SIZE {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_COMMITTEE_INVALID",
                format!(
                    "fixed committee requires {FIXED_COMMITTEE_SIZE} entries, received {}",
                    self.committee.len()
                ),
            ));
        }
        let mut peers = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        let mut configured_public_keys = Vec::with_capacity(FIXED_COMMITTEE_SIZE);
        for entry in &self.committee {
            let public_key = decode_public_key(&entry.consensus_public_key, "committee key")?;
            let address = parse_address(&entry.address, "committee address")?;
            configured_public_keys.push(public_key.clone());
            peers.push(CommitteePeer::new(
                ConsensusNodeId::from(public_key),
                address,
            ));
        }
        if private_key.public_key() != configured_public_keys[self.node.index] {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_LOCAL_KEY_MISMATCH",
                "local consensus private key does not match the indexed committee member",
            ));
        }

        let chain_id = ChainId::new(decode_array::<32>(&self.genesis.chain_id, "chain ID")?);
        let metadata = decode_hex(&self.genesis.metadata_hex, "genesis metadata")?;
        let metadata =
            GenesisMetadata::new(self.genesis.timestamp_ms, metadata).map_err(|error| {
                NodeConfigError::new(
                    "NODE_CONFIG_GENESIS_INVALID",
                    format!("genesis metadata exceeds its protocol bound: {error}"),
                )
            })?;
        let mechanisms = self
            .genesis
            .mechanisms
            .iter()
            .map(parse_mechanism)
            .collect::<Result<Vec<_>, _>>()?;
        let protocol =
            GenesisConfig::new(GenesisProtocolConfig::V1, mechanisms).map_err(|error| {
                NodeConfigError::new(
                    "NODE_CONFIG_GENESIS_INVALID",
                    format!("invalid genesis mechanism set: {error}"),
                )
            })?;
        let authorities = self
            .genesis
            .resolution_authorities
            .iter()
            .map(|encoded| decode_public_key(encoded, "resolution authority").map(ActorId::from))
            .collect::<Result<Vec<_>, _>>()?;
        let genesis_state = GenesisState::new(
            chain_id,
            protocol,
            ProtocolLimits::V1,
            metadata,
            authorities.clone(),
        )
        .map_err(|error| {
            NodeConfigError::new(
                "NODE_CONFIG_GENESIS_INVALID",
                format!("invalid genesis state: {error}"),
            )
        })?;
        let network_genesis =
            CommitteeNetworkGenesis::new(chain_id, peers, authorities).map_err(|error| {
                NodeConfigError::new(
                    "NODE_CONFIG_COMMITTEE_INVALID",
                    format!("invalid committee network: {error}"),
                )
            })?;

        validate_storage(&self.storage)?;
        let rpc_listen = parse_address(&self.rpc.listen, "RPC listen address")?;
        if self
            .committee
            .iter()
            .any(|peer| peer.address == self.rpc.listen)
        {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_RPC_INVALID",
                "RPC and authenticated committee addresses must be distinct",
            ));
        }
        let pending_limits = validate_pending(&self.pending_pool)?;
        let storage_directory = PathBuf::from(&self.storage.directory);
        let live = LiveNodeConfig::new(
            network_genesis,
            genesis_state,
            ConsensusNodeKey::new(private_key),
            pending_limits,
            self.storage.prefix.clone(),
        )
        .map(|live| live.with_rpc_listen(rpc_listen))
        .map_err(|error| {
            NodeConfigError::new(
                "NODE_CONFIG_INVALID",
                format!("live node configuration is inconsistent: {error}"),
            )
        })?;

        Ok(ValidatedNodeConfig {
            source: self,
            storage_directory,
            rpc_listen,
            live,
        })
    }

    /// Returns a structured copy safe for logs, RPC, and inspection output.
    pub fn redacted_value(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("node configuration serializes");
        value["node"]["consensus_private_key"] = Value::String("[REDACTED]".to_owned());
        value
    }

    pub fn to_pretty_json(&self) -> Result<Vec<u8>, NodeConfigError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            NodeConfigError::new(
                "NODE_CONFIG_ENCODE_FAILED",
                format!("cannot encode node configuration: {error}"),
            )
        })?;
        bytes.push(b'\n');
        if bytes.len() > MAX_NODE_CONFIG_BYTES {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_TOO_LARGE",
                "generated node configuration exceeds its document bound",
            ));
        }
        Ok(bytes)
    }

    pub fn node_name(&self) -> &str {
        &self.node.name
    }

    pub const fn node_index(&self) -> usize {
        self.node.index
    }

    pub fn storage_directory(&self) -> &str {
        &self.storage.directory
    }

    pub fn rpc_address(&self) -> &str {
        &self.rpc.listen
    }
}

/// Fully validated startup state. Constructing this value performs no I/O.
pub struct ValidatedNodeConfig {
    source: NodeConfig,
    storage_directory: PathBuf,
    rpc_listen: SocketAddr,
    live: LiveNodeConfig,
}

impl ValidatedNodeConfig {
    pub const fn source(&self) -> &NodeConfig {
        &self.source
    }

    pub fn storage_directory(&self) -> &std::path::Path {
        &self.storage_directory
    }

    pub const fn rpc_listen(&self) -> SocketAddr {
        self.rpc_listen
    }

    pub fn into_live(self) -> LiveNodeConfig {
        self.live
    }
}

/// Stable startup-configuration failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfigError {
    code: &'static str,
    message: String,
}

impl NodeConfigError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for NodeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NodeConfigError {}

fn validate_identifier(value: &str, maximum: usize, label: &str) -> Result<(), NodeConfigError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(NodeConfigError::new(
            "NODE_CONFIG_NAME_INVALID",
            format!("{label} must be 1..={maximum} ASCII letters, digits, '-' or '_'"),
        ));
    }
    Ok(())
}

fn validate_storage(storage: &StorageSection) -> Result<(), NodeConfigError> {
    if storage.directory.is_empty() || storage.directory.len() > MAX_STORAGE_PATH_BYTES {
        return Err(NodeConfigError::new(
            "NODE_CONFIG_STORAGE_INVALID",
            format!("storage directory must be 1..={MAX_STORAGE_PATH_BYTES} UTF-8 bytes"),
        ));
    }
    validate_identifier(&storage.prefix, MAX_STORAGE_PREFIX_BYTES, "storage prefix")
        .map_err(|error| NodeConfigError::new("NODE_CONFIG_STORAGE_INVALID", error.to_string()))
}

fn validate_pending(section: &PendingPoolSection) -> Result<PendingPoolLimits, NodeConfigError> {
    let invalid = section.max_actions == 0
        || section.max_actions > MAX_PENDING_ACTIONS
        || section.max_actions_per_actor == 0
        || section.max_actions_per_actor > section.max_actions
        || section.max_total_bytes < MAX_ACTION_BYTES
        || section.max_total_bytes > MAX_PENDING_BYTES
        || section.max_nonce_gap > MAX_NONCE_GAP;
    if invalid {
        return Err(NodeConfigError::new(
            "NODE_CONFIG_PENDING_LIMIT_INVALID",
            "pending-pool settings are zero, inconsistent, or outside startup bounds",
        ));
    }
    Ok(PendingPoolLimits::new(
        section.max_actions,
        section.max_actions_per_actor,
        section.max_total_bytes,
        section.max_nonce_gap,
    ))
}

fn parse_mechanism(entry: &MechanismEntry) -> Result<MechanismSelection, NodeConfigError> {
    let id = match entry.id.as_str() {
        "M00" => MechanismId::M00,
        "M01" => MechanismId::M01,
        _ => {
            return Err(NodeConfigError::new(
                "NODE_CONFIG_GENESIS_INVALID",
                format!("mechanism {} is not implemented", entry.id),
            ));
        }
    };
    if entry.version != "1.0.0" {
        return Err(NodeConfigError::new(
            "NODE_CONFIG_GENESIS_INVALID",
            format!(
                "mechanism {} version {} is unsupported",
                entry.id, entry.version
            ),
        ));
    }
    let config = decode_hex(&entry.config_hex, "mechanism config")?;
    let config = CanonicalMechanismConfig::new(config).map_err(|error| {
        NodeConfigError::new(
            "NODE_CONFIG_GENESIS_INVALID",
            format!("mechanism config exceeds its protocol bound: {error}"),
        )
    })?;
    Ok(MechanismSelection::new(
        id,
        MechanismVersion::V1_0_0,
        config,
    ))
}

fn parse_address(value: &str, label: &str) -> Result<SocketAddr, NodeConfigError> {
    let address = value.parse::<SocketAddr>().map_err(|error| {
        NodeConfigError::new(
            if label.starts_with("RPC") {
                "NODE_CONFIG_RPC_INVALID"
            } else {
                "NODE_CONFIG_COMMITTEE_INVALID"
            },
            format!("invalid {label} {value:?}: {error}"),
        )
    })?;
    if address.port() == 0 || address.ip().is_unspecified() {
        return Err(NodeConfigError::new(
            if label.starts_with("RPC") {
                "NODE_CONFIG_RPC_INVALID"
            } else {
                "NODE_CONFIG_COMMITTEE_INVALID"
            },
            format!("{label} must use a specified IP and nonzero port"),
        ));
    }
    Ok(address)
}

fn decode_private_key(value: &str) -> Result<ed25519::PrivateKey, NodeConfigError> {
    let bytes = decode_hex(value, "consensus private key")?;
    ed25519::PrivateKey::decode(bytes.as_slice()).map_err(|_| {
        NodeConfigError::new(
            "NODE_CONFIG_KEY_INVALID",
            "consensus private key must encode exactly one Ed25519 private key",
        )
    })
}

fn decode_public_key(value: &str, label: &str) -> Result<ed25519::PublicKey, NodeConfigError> {
    let bytes = decode_hex(value, label)?;
    ed25519::PublicKey::decode(bytes.as_slice()).map_err(|_| {
        NodeConfigError::new(
            "NODE_CONFIG_KEY_INVALID",
            format!("{label} must encode exactly one Ed25519 public key"),
        )
    })
}

fn decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], NodeConfigError> {
    let bytes = decode_hex(value, label)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        NodeConfigError::new(
            "NODE_CONFIG_GENESIS_INVALID",
            format!("{label} must be {N} bytes, received {}", bytes.len()),
        )
    })
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, NodeConfigError> {
    if !value.len().is_multiple_of(2) {
        return Err(NodeConfigError::new(
            "NODE_CONFIG_HEX_INVALID",
            format!("{label} has odd-length hexadecimal text"),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            match (high, low) {
                (Some(high), Some(low)) => Ok((high << 4) | low),
                _ => Err(NodeConfigError::new(
                    "NODE_CONFIG_HEX_INVALID",
                    format!("{label} must use lowercase hexadecimal"),
                )),
            }
        })
        .collect()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

impl ValidatedNodeConfig {
    /// Non-secret summary shared by CLI status and run responses.
    pub fn summary(&self) -> Value {
        json!({
            "node": self.source.node_name(),
            "node_index": self.source.node_index(),
            "storage_directory": self.source.storage_directory(),
            "rpc_address": self.source.rpc_address(),
            "committee_size": FIXED_COMMITTEE_SIZE,
            "schema_version": SCHEMA_VERSION,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_devnet_config_is_bounded_valid_and_redacted() {
        let config = NodeConfig::devnet(2, PathBuf::from("data/node-2")).unwrap();
        let encoded = config.to_pretty_json().unwrap();
        assert!(encoded.len() <= MAX_NODE_CONFIG_BYTES);
        let parsed = NodeConfig::parse(&encoded).unwrap();
        let validated = parsed.validate().unwrap();
        assert_eq!(validated.rpc_listen(), "127.0.0.1:32002".parse().unwrap());
        let inspected = config.redacted_value();
        assert_eq!(inspected["node"]["consensus_private_key"], "[REDACTED]");
        assert!(
            !serde_json::to_string(&inspected)
                .unwrap()
                .contains(&config.node.consensus_private_key)
        );
    }

    #[test]
    fn config_decoder_rejects_truncation_duplicate_unknown_and_oversized_input() {
        let encoded = NodeConfig::devnet(0, PathBuf::from("data/node-0"))
            .unwrap()
            .to_pretty_json()
            .unwrap();
        let document_end = encoded
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .unwrap()
            + 1;
        for length in 0..document_end {
            assert_eq!(
                NodeConfig::parse(&encoded[..length]).unwrap_err().code(),
                "NODE_CONFIG_PARSE_FAILED"
            );
        }

        let text = String::from_utf8(encoded).unwrap();
        let duplicate = text.replacen('{', "{\"schema_version\":1,", 1);
        assert_eq!(
            NodeConfig::parse(duplicate.as_bytes()).unwrap_err().code(),
            "NODE_CONFIG_PARSE_FAILED"
        );
        let unknown = text.replacen('{', "{\"unknown\":true,", 1);
        assert_eq!(
            NodeConfig::parse(unknown.as_bytes()).unwrap_err().code(),
            "NODE_CONFIG_PARSE_FAILED"
        );
        assert_eq!(
            NodeConfig::parse(&vec![b' '; MAX_NODE_CONFIG_BYTES + 1])
                .unwrap_err()
                .code(),
            "NODE_CONFIG_TOO_LARGE"
        );
    }

    #[test]
    fn all_validation_finishes_before_storage_can_be_observed() {
        let mut config = NodeConfig::devnet(0, PathBuf::from("never-created")).unwrap();
        config.committee.pop();
        let error = config.validate().err().unwrap();
        assert_eq!(error.code(), "NODE_CONFIG_COMMITTEE_INVALID");
        assert!(!std::path::Path::new("never-created").exists());
    }
}
