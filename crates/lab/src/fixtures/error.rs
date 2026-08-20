use std::{error::Error, fmt, io, path::PathBuf};

use super::IntegrityHash;

/// A strict fixture loading or integrity failure.
#[derive(Debug)]
pub enum FixtureError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    Invalid {
        subject: String,
        reason: String,
    },
    HashMismatch {
        subject: String,
        expected: IntegrityHash,
        actual: IntegrityHash,
    },
    Git {
        repository: PathBuf,
        operation: &'static str,
        message: String,
    },
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
            Self::Json { path, source } => {
                write!(
                    formatter,
                    "invalid fixture JSON in {}: {source}",
                    path.display()
                )
            }
            Self::Invalid { subject, reason } => {
                write!(formatter, "invalid {subject}: {reason}")
            }
            Self::HashMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "integrity mismatch for {subject}: expected {expected}, got {actual}"
            ),
            Self::Git {
                repository,
                operation,
                message,
            } => write!(
                formatter,
                "Git {operation} failed for {}: {message}",
                repository.display()
            ),
        }
    }
}

impl Error for FixtureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Invalid { .. } | Self::HashMismatch { .. } | Self::Git { .. } => None,
        }
    }
}
