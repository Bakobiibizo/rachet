//! Network actor identity generation and role-bound key persistence.

use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Signer as _, ed25519};
use rachet_core::primitives::ActorId;
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const ACTOR_KEY_MAGIC: &[u8] = b"rachet-network-actor-key-v1\0";
const PRIVATE_KEY_BYTES: usize = 32;
const ACTOR_KEY_BYTES: usize = ACTOR_KEY_MAGIC.len() + PRIVATE_KEY_BYTES;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_MODE_MASK: u32 = 0o077;

/// An Ed25519 identity restricted to signing network actions.
///
/// The private key is deliberately inaccessible outside the client crate. Its
/// debug representation contains only the public actor identifier.
pub struct ActorIdentity {
    private_key: ed25519::PrivateKey,
}

impl ActorIdentity {
    /// Generates an actor key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut bytes = Zeroizing::new([0_u8; PRIVATE_KEY_BYTES]);
        getrandom::fill(bytes.as_mut()).map_err(|error| IdentityError::Entropy {
            message: error.to_string(),
        })?;
        let private_key = ed25519::PrivateKey::decode(bytes.as_slice()).map_err(|_| {
            IdentityError::InvalidFormat {
                message: "operating system randomness did not form an Ed25519 key".to_owned(),
            }
        })?;
        Ok(Self { private_key })
    }

    /// Generates and exclusively persists a new actor identity.
    ///
    /// Existing paths are never replaced. The actor-role header intentionally
    /// makes this file incompatible with raw consensus-key files.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        let identity = Self::generate()?;
        identity.persist_new(path)?;
        Ok(identity)
    }

    /// Loads an actor identity after validating file type, mode, and role.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path).map_err(|error| IdentityError::Read {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        if !metadata.file_type().is_file() {
            return Err(IdentityError::InvalidFileType {
                path: path.to_path_buf(),
            });
        }
        let mut file = File::open(path).map_err(|error| IdentityError::Read {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        let opened = file.metadata().map_err(|error| IdentityError::Read {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(IdentityError::InvalidFileType {
                path: path.to_path_buf(),
            });
        }
        let mode = opened.permissions().mode() & 0o777;
        if mode & PRIVATE_MODE_MASK != 0 {
            return Err(IdentityError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        if opened.len() != ACTOR_KEY_BYTES as u64 {
            return Err(IdentityError::InvalidFormat {
                message: format!(
                    "actor key file must be exactly {ACTOR_KEY_BYTES} bytes, received {}",
                    opened.len()
                ),
            });
        }

        let mut bytes = Zeroizing::new(Vec::with_capacity(ACTOR_KEY_BYTES));
        file.read_to_end(&mut bytes)
            .map_err(|error| IdentityError::Read {
                path: path.to_path_buf(),
                message: error.to_string(),
            })?;
        if bytes.len() != ACTOR_KEY_BYTES || !bytes.starts_with(ACTOR_KEY_MAGIC) {
            return Err(IdentityError::InvalidFormat {
                message: "key is not a role-bound rachet network actor key".to_owned(),
            });
        }
        let private_key =
            ed25519::PrivateKey::decode(&bytes[ACTOR_KEY_MAGIC.len()..]).map_err(|_| {
                IdentityError::InvalidFormat {
                    message: "actor key contains malformed Ed25519 private material".to_owned(),
                }
            })?;
        Ok(Self { private_key })
    }

    /// Returns the public network actor identifier.
    pub fn actor_id(&self) -> ActorId {
        ActorId::from(self.private_key.public_key())
    }

    pub(crate) fn private_key(&self) -> &ed25519::PrivateKey {
        &self.private_key
    }

    fn persist_new(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(parent)
                .map_err(|error| IdentityError::Create {
                    path: parent.to_path_buf(),
                    message: error.to_string(),
                })?;
        }

        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(PRIVATE_FILE_MODE);
        let mut file = options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                IdentityError::AlreadyExists {
                    path: path.to_path_buf(),
                }
            } else {
                IdentityError::Create {
                    path: path.to_path_buf(),
                    message: error.to_string(),
                }
            }
        })?;

        let private_bytes = Zeroizing::new(self.private_key.encode().to_vec());
        let write_result = (|| {
            file.write_all(ACTOR_KEY_MAGIC)?;
            file.write_all(private_bytes.as_slice())?;
            file.sync_all()
        })();
        if let Err(error) = write_result {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(IdentityError::Create {
                path: path.to_path_buf(),
                message: error.to_string(),
            });
        }
        Ok(())
    }
}

impl fmt::Debug for ActorIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActorIdentity")
            .field("actor_id", &self.actor_id())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Stable actor identity generation and storage failures.
#[derive(Debug)]
pub enum IdentityError {
    /// The operating system could not provide cryptographic randomness.
    Entropy { message: String },
    /// The destination already exists and was not replaced.
    AlreadyExists { path: PathBuf },
    /// A key or parent directory could not be created.
    Create { path: PathBuf, message: String },
    /// A key file could not be read.
    Read { path: PathBuf, message: String },
    /// The path is not a regular file (including symbolic links).
    InvalidFileType { path: PathBuf },
    /// Group or other users have access to the key file.
    InsecurePermissions { path: PathBuf, mode: u32 },
    /// The file is malformed or belongs to another key role.
    InvalidFormat { message: String },
}

impl IdentityError {
    /// Returns the stable machine-readable storage error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Entropy { .. } => "IDENTITY_ENTROPY_UNAVAILABLE",
            Self::AlreadyExists { .. } => "IDENTITY_KEY_EXISTS",
            Self::Create { .. } => "IDENTITY_KEY_CREATE_FAILED",
            Self::Read { .. } => "IDENTITY_KEY_READ_FAILED",
            Self::InvalidFileType { .. } => "IDENTITY_KEY_TYPE_INVALID",
            Self::InsecurePermissions { .. } => "IDENTITY_KEY_PERMISSIONS_INVALID",
            Self::InvalidFormat { .. } => "IDENTITY_KEY_FORMAT_INVALID",
        }
    }

    /// Returns the affected path when the failure has one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::AlreadyExists { path }
            | Self::Create { path, .. }
            | Self::Read { path, .. }
            | Self::InvalidFileType { path }
            | Self::InsecurePermissions { path, .. } => Some(path),
            Self::Entropy { .. } | Self::InvalidFormat { .. } => None,
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy { message } => {
                write!(formatter, "secure randomness unavailable: {message}")
            }
            Self::AlreadyExists { path } => write!(
                formatter,
                "actor key {} already exists and was not replaced",
                path.display()
            ),
            Self::Create { path, message } => {
                write!(
                    formatter,
                    "cannot create actor key {}: {message}",
                    path.display()
                )
            }
            Self::Read { path, message } => {
                write!(
                    formatter,
                    "cannot read actor key {}: {message}",
                    path.display()
                )
            }
            Self::InvalidFileType { path } => {
                write!(
                    formatter,
                    "actor key {} is not a regular file",
                    path.display()
                )
            }
            Self::InsecurePermissions { path, mode } => write!(
                formatter,
                "actor key {} has insecure mode {mode:03o}; expected no group or other access",
                path.display()
            ),
            Self::InvalidFormat { message } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must follow epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rachet-client-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn keys_round_trip_with_private_permissions_and_redacted_debug() {
        let directory = temporary_path("round-trip");
        let path = directory.join("actor.key");
        let created = ActorIdentity::create(&path).unwrap();
        let actor_id = created.actor_id();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(ActorIdentity::load(&path).unwrap().actor_id(), actor_id);

        let debug = format!("{created:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&format!("{:?}", created.private_key.encode())));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn existing_insecure_and_non_actor_key_files_are_rejected() {
        let directory = temporary_path("reject");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("actor.key");
        let first = ActorIdentity::create(&path).unwrap();
        assert!(matches!(
            ActorIdentity::create(&path),
            Err(IdentityError::AlreadyExists { .. })
        ));
        assert_eq!(
            ActorIdentity::load(&path).unwrap().actor_id(),
            first.actor_id()
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ActorIdentity::load(&path),
            Err(IdentityError::InsecurePermissions { .. })
        ));

        let raw = directory.join("consensus.key");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options.open(&raw).unwrap().write_all(&[7_u8; 32]).unwrap();
        assert!(matches!(
            ActorIdentity::load(&raw),
            Err(IdentityError::InvalidFormat { .. })
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
