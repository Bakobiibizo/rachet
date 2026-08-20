use rachet_client::identity::ActorIdentity;
use rachet_operator::{
    budget::{ResourceBudget, ResourceUsage},
    host::{HostError, OperatorAccess, OperatorHost, ProtectedPaths},
    manifest::{
        AgentConfiguration, CommunicationChannel, IdentityConstraints, IndependenceClaim,
        IndependenceDeclaration, InformationPolicy, LearningPolicy, OperatorKind,
        OperatorRuntimeConfig, OperatorSpec, POPULATION_SCHEMA_VERSION, PRODUCTIVE_OBJECTIVE,
        PopulationManifest,
    },
};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_path(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rachet-operator-{name}-{}-{unique}",
        std::process::id()
    ))
}

fn git(repository: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn repository(root: &Path) -> PathBuf {
    let repository = root.join("public-repository");
    fs::create_dir_all(&repository).unwrap();
    git(&repository, &["init", "--quiet"]);
    git(&repository, &["config", "user.name", "Rachet Test"]);
    git(
        &repository,
        &["config", "user.email", "rachet@example.invalid"],
    );
    fs::write(repository.join("README.md"), "public fixture\n").unwrap();
    git(&repository, &["add", "README.md"]);
    git(&repository, &["commit", "--quiet", "-m", "fixture"]);
    repository
}

fn operator(operator_id: &str) -> OperatorSpec {
    OperatorSpec {
        operator_id: operator_id.to_owned(),
        role: "validation_operator".to_owned(),
        objective: PRODUCTIVE_OBJECTIVE.to_owned(),
        operator_kind: OperatorKind::Productive,
        agent: AgentConfiguration {
            provider: "test-provider".to_owned(),
            model: format!("model-{operator_id}"),
            model_family: format!("family-{operator_id}"),
            random_seed: format!("seed-{operator_id}"),
            tool_harness: "agentctl".to_owned(),
            system_prompt_sha256: "ab".repeat(32),
        },
        information: {
            let mut policy = InformationPolicy::standard_validation("independent-inspection");
            if operator_id == "gamma" {
                policy.filesystem_access.retain(|access| {
                    *access != rachet_operator::manifest::FilesystemAccess::PrivateScratch
                });
            }
            policy
        },
        learning: LearningPolicy::adaptive_validation(),
        communication_channels: if operator_id == "gamma" {
            Vec::new()
        } else {
            vec!["declared-alpha-beta".to_owned()]
        },
        customer_relationship: "none".to_owned(),
        resource_budget: ResourceBudget {
            model_calls: 2,
            tool_calls: 5,
            validation_seconds: 10,
        },
        identity_constraints: IdentityConstraints::validation_operator(),
        independence: IndependenceDeclaration {
            model_family: IndependenceClaim::Independent,
            system_prompt: IndependenceClaim::Shared {
                group: "shared-prompt".to_owned(),
            },
            random_seed: IndependenceClaim::Independent,
            tool_harness: IndependenceClaim::Shared {
                group: "shared-agentctl".to_owned(),
            },
            memory: IndependenceClaim::Independent,
            worktree: IndependenceClaim::Independent,
            evidence_method: IndependenceClaim::Shared {
                group: "shared-inspection".to_owned(),
            },
            communication_channel: if operator_id == "gamma" {
                IndependenceClaim::Independent
            } else {
                IndependenceClaim::Shared {
                    group: "declared-alpha-beta".to_owned(),
                }
            },
            customer_relationship: IndependenceClaim::Independent,
        },
    }
}

fn manifest() -> PopulationManifest {
    PopulationManifest {
        schema_version: POPULATION_SCHEMA_VERSION.to_owned(),
        operators: ["alpha", "beta", "gamma"]
            .into_iter()
            .map(operator)
            .collect(),
        communication_channels: vec![CommunicationChannel {
            channel_id: "declared-alpha-beta".to_owned(),
            participants: vec!["alpha".to_owned(), "beta".to_owned()],
        }],
    }
}

#[test]
fn three_operators_have_distinct_identities_homes_worktrees_and_bounded_access() {
    let root = temporary_path("population");
    fs::create_dir_all(&root).unwrap();
    let repository = repository(&root);
    let hidden = root.join("hidden-evaluator");
    let consensus = root.join("consensus-keys");
    fs::create_dir_all(&hidden).unwrap();
    fs::create_dir_all(&consensus).unwrap();
    fs::write(hidden.join("truth.json"), br#"{"verdict":"fail"}"#).unwrap();
    fs::write(consensus.join("node.key"), b"consensus-private-material").unwrap();

    let protected = ProtectedPaths::new(vec![consensus.clone()], vec![hidden.clone()]).unwrap();
    let host =
        OperatorHost::create(root.join("population"), &repository, "HEAD", protected).unwrap();
    let mut population = host.provision(manifest()).unwrap();
    assert_eq!(population.operators().len(), 3);
    assert_eq!(population.independence_report().identities, 3);
    assert_eq!(population.independence_report().model_families, 3);
    assert_eq!(population.independence_report().system_prompts, 1);
    assert!(!population.independence_report().fully_independent);

    let actor_ids = population
        .operators()
        .values()
        .map(|operator| operator.actor_id().to_owned())
        .collect::<BTreeSet<_>>();
    let homes = population
        .operators()
        .values()
        .map(|operator| operator.home().to_owned())
        .collect::<BTreeSet<_>>();
    let worktrees = population
        .operators()
        .values()
        .map(|operator| operator.worktree().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actor_ids.len(), 3);
    assert_eq!(homes.len(), 3);
    assert_eq!(worktrees.len(), 3);

    for operator in population.operators().values() {
        assert_eq!(
            fs::metadata(operator.home()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(operator.config_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let config_bytes = fs::read(operator.config_path()).unwrap();
        let config: OperatorRuntimeConfig = serde_json::from_slice(&config_bytes).unwrap();
        assert_eq!(config.operator_id, operator.operator_id());
        assert_eq!(config.actor_id, operator.actor_id());
        assert_eq!(
            ActorIdentity::load(&config.actor_key)
                .unwrap()
                .actor_id()
                .as_bytes(),
            decode_hex(operator.actor_id()).as_slice()
        );
        assert!(
            !config_bytes
                .windows(hidden.as_os_str().len())
                .any(|window| { window == hidden.as_os_str().as_encoded_bytes() })
        );
        assert!(
            !config_bytes
                .windows(consensus.as_os_str().len())
                .any(|window| { window == consensus.as_os_str().as_encoded_bytes() })
        );
        assert!(operator.worktree().join("README.md").is_file());
    }

    population
        .operator("alpha")
        .unwrap()
        .write_file(OperatorAccess::Memory, "private-note", b"alpha only")
        .unwrap();
    assert_eq!(
        population
            .operator("alpha")
            .unwrap()
            .read_file(OperatorAccess::Memory, "private-note")
            .unwrap(),
        b"alpha only"
    );
    assert!(matches!(
        population.operator("beta").unwrap().authorize_existing(
            OperatorAccess::Memory,
            "../../../alpha/home/memory/private-note"
        ),
        Err(HostError::AccessDenied(_))
    ));

    let beta_memory = population.operator("beta").unwrap().home().join("memory");
    symlink(hidden.join("truth.json"), beta_memory.join("truth-link")).unwrap();
    assert!(matches!(
        population
            .operator("beta")
            .unwrap()
            .read_file(OperatorAccess::Memory, "truth-link"),
        Err(HostError::AccessDenied(_))
    ));
    symlink(
        consensus.join("node.key"),
        beta_memory.join("consensus-link"),
    )
    .unwrap();
    assert!(matches!(
        population
            .operator("beta")
            .unwrap()
            .read_file(OperatorAccess::Memory, "consensus-link"),
        Err(HostError::AccessDenied(_))
    ));

    population
        .operator("alpha")
        .unwrap()
        .write_file(
            OperatorAccess::Communication("declared-alpha-beta"),
            "message",
            b"declared communication",
        )
        .unwrap();
    assert_eq!(
        population
            .operator("beta")
            .unwrap()
            .read_file(
                OperatorAccess::Communication("declared-alpha-beta"),
                "message"
            )
            .unwrap(),
        b"declared communication"
    );
    assert!(matches!(
        population.operator("gamma").unwrap().read_file(
            OperatorAccess::Communication("declared-alpha-beta"),
            "message"
        ),
        Err(HostError::UndeclaredCommunication(_))
    ));
    assert!(matches!(
        population.operator("gamma").unwrap().write_file(
            OperatorAccess::Scratch,
            "undeclared",
            b"must be rejected",
        ),
        Err(HostError::AccessDenied(_))
    ));

    let alpha = population.operator_mut("alpha").unwrap();
    alpha
        .charge(ResourceUsage {
            model_calls: 2,
            tool_calls: 3,
            validation_seconds: 10,
        })
        .unwrap();
    let prior = *alpha.budget();
    assert!(
        alpha
            .charge(ResourceUsage {
                model_calls: 1,
                tool_calls: 0,
                validation_seconds: 0,
            })
            .is_err()
    );
    assert_eq!(*alpha.budget(), prior);

    population.destroy().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn protected_storage_cannot_contain_source_or_operator_roots() {
    let root = temporary_path("protected-overlap");
    fs::create_dir_all(&root).unwrap();
    let repository = repository(&root);
    let hidden = root.join("hidden");
    fs::create_dir_all(&hidden).unwrap();

    let protected = ProtectedPaths::new(Vec::new(), vec![repository.clone()]).unwrap();
    assert!(matches!(
        OperatorHost::create(root.join("population-a"), &repository, "HEAD", protected),
        Err(HostError::ProtectedPathOverlap {
            protected_kind: "hidden_evaluator",
            ..
        })
    ));

    let protected = ProtectedPaths::new(Vec::new(), vec![hidden.clone()]).unwrap();
    assert!(matches!(
        OperatorHost::create(hidden.join("population-b"), &repository, "HEAD", protected),
        Err(HostError::ProtectedPathOverlap {
            protected_kind: "hidden_evaluator",
            ..
        })
    ));
    assert!(!hidden.join("population-b").exists());
    fs::remove_dir_all(root).unwrap();
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}
