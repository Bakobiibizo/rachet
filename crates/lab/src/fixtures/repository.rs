use std::{collections::BTreeSet, path::Path, process::Command};

use sha2::{Digest as _, Sha256};

use super::{FixtureError, IntegrityHash, RepositoryFixture};

const REPOSITORY_HASH_DOMAIN: &[u8] = b"rachet/repository-fixture/v1\0";
const MAX_TRACKED_OBJECTS: usize = 100_000;

pub(super) fn verify_repository(
    repository: &Path,
    fixture: &RepositoryFixture,
) -> Result<(), FixtureError> {
    validate_object_id("base commit", &fixture.base_commit)?;
    validate_object_id("candidate commit", &fixture.candidate_commit)?;
    if fixture.base_commit.len() != fixture.candidate_commit.len() {
        return Err(invalid(
            "repository commits",
            "base and candidate use different Git object formats",
        ));
    }

    let actual_base = git_text(
        repository,
        "resolve base commit",
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", fixture.base_commit),
        ],
    )?;
    let actual_candidate = git_text(
        repository,
        "resolve candidate commit",
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", fixture.candidate_commit),
        ],
    )?;
    if actual_base != fixture.base_commit || actual_candidate != fixture.candidate_commit {
        return Err(invalid(
            "repository commits",
            "commit identifiers must be full canonical object IDs",
        ));
    }

    git(
        repository,
        "check candidate ancestry",
        &[
            "merge-base",
            "--is-ancestor",
            &fixture.base_commit,
            &fixture.candidate_commit,
        ],
    )?;

    let actual =
        repository_integrity_hash(repository, &fixture.base_commit, &fixture.candidate_commit)?;
    if actual != fixture.integrity_sha256 {
        return Err(FixtureError::HashMismatch {
            subject: format!("repository {}", repository.display()),
            expected: fixture.integrity_sha256,
            actual,
        });
    }
    Ok(())
}

/// Computes the v1 repository fixture digest from two real Git commits.
///
/// The digest includes each raw commit object, each recursive `ls-tree -z`
/// listing, and the exact bytes of every unique blob referenced by either
/// tree. Length framing prevents concatenation ambiguity.
pub fn repository_integrity_hash(
    repository: &Path,
    base_commit: &str,
    candidate_commit: &str,
) -> Result<IntegrityHash, FixtureError> {
    validate_object_id("base commit", base_commit)?;
    validate_object_id("candidate commit", candidate_commit)?;

    let mut hasher = Sha256::new();
    hasher.update(REPOSITORY_HASH_DOMAIN);
    let mut blobs = BTreeSet::new();

    for (label, commit) in [
        (b"base".as_slice(), base_commit),
        (b"candidate", candidate_commit),
    ] {
        hash_framed(&mut hasher, label);
        hash_framed(&mut hasher, commit.as_bytes());

        let commit_object = git(
            repository,
            "read commit object",
            &["cat-file", "commit", commit],
        )?;
        hash_framed(&mut hasher, &commit_object);

        let tree = git(
            repository,
            "list commit tree",
            &["ls-tree", "-r", "-z", "--full-tree", commit],
        )?;
        hash_framed(&mut hasher, &tree);
        collect_blob_ids(&tree, &mut blobs)?;
        if blobs.len() > MAX_TRACKED_OBJECTS {
            return Err(invalid(
                "repository tree",
                format!("contains more than {MAX_TRACKED_OBJECTS} unique blobs"),
            ));
        }
    }

    for blob in blobs {
        hash_framed(&mut hasher, blob.as_bytes());
        let content = git(repository, "read blob", &["cat-file", "blob", &blob])?;
        hash_framed(&mut hasher, &content);
    }

    Ok(IntegrityHash::from_bytes(hasher.finalize().into()))
}

fn collect_blob_ids(tree: &[u8], blobs: &mut BTreeSet<String>) -> Result<(), FixtureError> {
    for entry in tree
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let separator = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| invalid("Git tree", "ls-tree entry has no path separator"))?;
        let metadata = &entry[..separator];
        let metadata = std::str::from_utf8(metadata)
            .map_err(|_| invalid("Git tree", "ls-tree metadata is not UTF-8"))?;
        let mut fields = metadata.split(' ');
        let _mode = fields.next();
        let object_type = fields.next();
        let object_id = fields.next();
        if fields.next().is_some() || object_type.is_none() || object_id.is_none() {
            return Err(invalid("Git tree", "malformed ls-tree metadata"));
        }
        if object_type == Some("blob") {
            blobs.insert(object_id.unwrap().to_owned());
        }
    }
    Ok(())
}

fn hash_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn validate_object_id(subject: &str, value: &str) -> Result<(), FixtureError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            subject,
            "must be a full lowercase SHA-1 or SHA-256 Git object ID",
        ));
    }
    Ok(())
}

fn git_text(
    repository: &Path,
    operation: &'static str,
    args: &[&str],
) -> Result<String, FixtureError> {
    let output = git(repository, operation, args)?;
    String::from_utf8(output)
        .map(|value| value.trim_end().to_owned())
        .map_err(|_| FixtureError::Git {
            repository: repository.to_owned(),
            operation,
            message: "command output was not UTF-8".to_owned(),
        })
}

fn git(repository: &Path, operation: &'static str, args: &[&str]) -> Result<Vec<u8>, FixtureError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|source| FixtureError::Io {
            operation: "execute Git",
            path: repository.to_owned(),
            source,
        })?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(FixtureError::Git {
            repository: repository.to_owned(),
            operation,
            message: if message.is_empty() {
                format!("command exited with {}", output.status)
            } else {
                message
            },
        });
    }
    Ok(output.stdout)
}

fn invalid(subject: impl Into<String>, reason: impl Into<String>) -> FixtureError {
    FixtureError::Invalid {
        subject: subject.into(),
        reason: reason.into(),
    }
}
