//! Bounded blocking HTTP transport for the node's public JSON RPC.

use reqwest::{StatusCode, Url, blocking::Client};
use serde_json::{Value, json};
use std::{fmt, io::Read as _, time::Duration};

const MAX_RPC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Client for the section 20.1 node RPC surface.
#[derive(Clone, Debug)]
pub struct NodeClient {
    base_url: Url,
    http: Client,
}

impl NodeClient {
    /// Constructs a bounded client for an HTTP(S) node endpoint.
    pub fn new(base_url: &str) -> Result<Self, TransportError> {
        let mut base_url = Url::parse(base_url).map_err(|error| TransportError::InvalidUrl {
            message: error.to_string(),
        })?;
        if !matches!(base_url.scheme(), "http" | "https") || base_url.host_str().is_none() {
            return Err(TransportError::InvalidUrl {
                message: "node URL must be an absolute http:// or https:// URL".to_owned(),
            });
        }
        if base_url.query().is_some() || base_url.fragment().is_some() {
            return Err(TransportError::InvalidUrl {
                message: "node URL cannot contain a query or fragment".to_owned(),
            });
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let http = Client::builder()
            .timeout(RPC_TIMEOUT)
            .build()
            .map_err(|error| TransportError::RequestFailed {
                message: error.to_string(),
            })?;
        Ok(Self { base_url, http })
    }

    /// Submits canonical signed-action bytes through the node ingress wrapper.
    pub fn submit_action(&self, canonical_action_hex: &str) -> Result<Value, TransportError> {
        self.post(
            "v1/actions",
            &json!({"canonical_action": canonical_action_hex}),
        )
    }

    /// Returns all finalized public job projections.
    pub fn jobs(&self) -> Result<Value, TransportError> {
        self.get("v1/jobs")
    }

    /// Returns one finalized public job projection.
    pub fn job(&self, job_id_hex: &str) -> Result<Value, TransportError> {
        self.get(&format!("v1/jobs/{job_id_hex}"))
    }

    /// Returns public canonical nonce state for an actor.
    pub fn actor(&self, actor_id_hex: &str) -> Result<Value, TransportError> {
        self.get(&format!("v1/actors/{actor_id_hex}"))
    }

    /// Returns one block from the node's finalized immutable archive index.
    pub fn block(&self, height: u64) -> Result<Value, TransportError> {
        self.get(&format!("v1/blocks/{height}"))
    }

    /// Returns the latest finalized logical and QMDB roots.
    pub fn state_root(&self) -> Result<Value, TransportError> {
        self.get("v1/state/root")
    }

    /// Returns retained finalized state for one genesis-selected mechanism.
    pub fn mechanism(&self, mechanism_id: &str) -> Result<Value, TransportError> {
        self.get(&format!("v1/state/mechanisms/{mechanism_id}"))
    }

    /// Replays all retained finalized blocks through the node's pure executor.
    pub fn verify_replay(&self) -> Result<Value, TransportError> {
        self.get("v1/replay/verify")
    }

    /// Returns public node health and finalized-height state.
    pub fn health(&self) -> Result<Value, TransportError> {
        self.get("v1/health")
    }

    fn get(&self, path: &str) -> Result<Value, TransportError> {
        let url = self.endpoint(path)?;
        let response = self
            .http
            .get(url)
            .header("accept", "application/json")
            .send()
            .map_err(request_error)?;
        decode_response(response)
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, TransportError> {
        let url = self.endpoint(path)?;
        let response = self
            .http
            .post(url)
            .header("accept", "application/json")
            .json(body)
            .send()
            .map_err(request_error)?;
        decode_response(response)
    }

    fn endpoint(&self, path: &str) -> Result<Url, TransportError> {
        self.base_url
            .join(path)
            .map_err(|error| TransportError::InvalidUrl {
                message: error.to_string(),
            })
    }
}

/// Stable local and server-supplied RPC failures.
#[derive(Clone, Debug, PartialEq)]
pub enum TransportError {
    InvalidUrl {
        message: String,
    },
    RequestFailed {
        message: String,
    },
    ResponseTooLarge {
        maximum: usize,
    },
    MalformedResponse {
        message: String,
    },
    Remote {
        status: u16,
        code: String,
        message: String,
        details: Value,
    },
}

impl TransportError {
    /// Returns a stable machine-readable code, preserving a server error code exactly.
    pub fn code(&self) -> &str {
        match self {
            Self::InvalidUrl { .. } => "RPC_URL_INVALID",
            Self::RequestFailed { .. } => "RPC_TRANSPORT_FAILED",
            Self::ResponseTooLarge { .. } => "RPC_RESPONSE_TOO_LARGE",
            Self::MalformedResponse { .. } => "RPC_RESPONSE_MALFORMED",
            Self::Remote { code, .. } => code,
        }
    }

    /// Returns structured diagnostics safe for the CLI error envelope.
    pub fn details(&self) -> Value {
        match self {
            Self::ResponseTooLarge { maximum } => json!({"maximum_bytes": maximum}),
            Self::Remote {
                status, details, ..
            } => {
                let mut details = details.clone();
                if let Some(object) = details.as_object_mut() {
                    object.insert("http_status".to_owned(), Value::from(*status));
                    details
                } else {
                    json!({"http_status": status, "server_details": details})
                }
            }
            Self::InvalidUrl { .. }
            | Self::RequestFailed { .. }
            | Self::MalformedResponse { .. } => json!({}),
        }
    }

    /// Returns whether this is a specific server-supplied failure.
    pub fn is_remote_code(&self, expected: &str) -> bool {
        matches!(self, Self::Remote { code, .. } if code == expected)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl { message } => write!(formatter, "invalid node URL: {message}"),
            Self::RequestFailed { message } => {
                write!(formatter, "node RPC request failed: {message}")
            }
            Self::ResponseTooLarge { maximum } => {
                write!(formatter, "node RPC response exceeds {maximum} bytes")
            }
            Self::MalformedResponse { message } => {
                write!(formatter, "node RPC returned malformed JSON: {message}")
            }
            Self::Remote { message, .. } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for TransportError {}

fn request_error(error: reqwest::Error) -> TransportError {
    TransportError::RequestFailed {
        message: error.to_string(),
    }
}

fn decode_response(mut response: reqwest::blocking::Response) -> Result<Value, TransportError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
    {
        return Err(TransportError::ResponseTooLarge {
            maximum: MAX_RPC_RESPONSE_BYTES,
        });
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take((MAX_RPC_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| TransportError::RequestFailed {
            message: error.to_string(),
        })?;
    if bytes.len() > MAX_RPC_RESPONSE_BYTES {
        return Err(TransportError::ResponseTooLarge {
            maximum: MAX_RPC_RESPONSE_BYTES,
        });
    }
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|error| TransportError::MalformedResponse {
            message: error.to_string(),
        })?;
    decode_envelope(status, value)
}

fn decode_envelope(status: StatusCode, value: Value) -> Result<Value, TransportError> {
    if status.is_success() {
        if value.get("ok").and_then(Value::as_bool) == Some(true) {
            return value
                .get("result")
                .cloned()
                .ok_or_else(|| TransportError::MalformedResponse {
                    message: "successful response has no result".to_owned(),
                });
        }
        return Err(TransportError::MalformedResponse {
            message: "successful response does not use the RPC success envelope".to_owned(),
        });
    }

    let error = value
        .get("error")
        .and_then(Value::as_object)
        .ok_or_else(|| TransportError::MalformedResponse {
            message: format!("HTTP {} response has no error envelope", status.as_u16()),
        })?;
    let code = error.get("code").and_then(Value::as_str).ok_or_else(|| {
        TransportError::MalformedResponse {
            message: "RPC error has no string code".to_owned(),
        }
    })?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| TransportError::MalformedResponse {
            message: "RPC error has no string message".to_owned(),
        })?;
    Err(TransportError::Remote {
        status: status.as_u16(),
        code: code.to_owned(),
        message: message.to_owned(),
        details: error.get("details").cloned().unwrap_or_else(|| json!({})),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write as _, net::TcpListener, thread};

    fn server(status: &str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_owned();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        format!("http://{address}")
    }

    #[test]
    fn success_results_and_remote_error_codes_are_preserved() {
        let url = server("200 OK", r#"{"ok":true,"result":{"count":0,"jobs":[]}}"#);
        assert_eq!(NodeClient::new(&url).unwrap().jobs().unwrap()["count"], 0);

        let url = server(
            "422 Unprocessable Entity",
            r#"{"error":{"code":"JOB_LIFECYCLE_OPEN","message":"window is open","details":{"height":4}}}"#,
        );
        let error = NodeClient::new(&url).unwrap().jobs().unwrap_err();
        assert_eq!(error.code(), "JOB_LIFECYCLE_OPEN");
        assert_eq!(error.details()["height"], 4);
        assert_eq!(error.details()["http_status"], 422);
    }

    #[test]
    fn url_and_envelope_failures_have_stable_local_codes() {
        assert_eq!(
            NodeClient::new("not a URL").unwrap_err().code(),
            "RPC_URL_INVALID"
        );
        let url = server("200 OK", r#"{"jobs":[]}"#);
        assert_eq!(
            NodeClient::new(&url).unwrap().jobs().unwrap_err().code(),
            "RPC_RESPONSE_MALFORMED"
        );
    }
}
