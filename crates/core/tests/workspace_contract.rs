use std::{fs, path::Path};

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("core crate must be two levels below the workspace root")
}

#[test]
fn prescribed_workspace_layout_exists() {
    let root = workspace_root();
    let required_paths = [
        "AGENTS.md",
        "README.md",
        ".github/workflows/ci.yml",
        "crates/core",
        "crates/mechanisms",
        "crates/chain",
        "crates/client",
        "crates/operator",
        "crates/lab",
        "crates/cli",
        "bins/rcht-node",
        "bins/rchtctl",
        "bins/rcht-operator",
        "bins/rcht-lab",
        "configs/devnet",
        "configs/experiments",
        "schemas/operator-observation",
        "schemas/operator-decision",
        "schemas/experiment",
        "fixtures/repositories",
        "fixtures/jobs-public",
        "fixtures/ground-truth-private",
        "experiments",
        "exploits",
        "conformance",
        "docs",
    ];

    for path in required_paths {
        assert!(root.join(path).exists(), "required path is missing: {path}");
    }
}

#[test]
#[should_panic(expected = "attempt to add with overflow")]
fn active_test_profile_panics_on_overflow() {
    let maximum = std::hint::black_box(u8::MAX);
    let one = std::hint::black_box(1_u8);
    let _overflow = maximum + one;
}

#[test]
fn every_build_profile_checks_overflow() {
    let manifest = fs::read_to_string(workspace_root().join("Cargo.toml"))
        .expect("workspace manifest must be readable");

    for profile in ["dev", "test", "release"] {
        let section = format!("[profile.{profile}]");
        assert!(manifest.contains(&section), "missing {section}");
    }
    assert_eq!(
        manifest.matches("overflow-checks = true").count(),
        3,
        "dev, test, and release must each enable overflow checks"
    );
}

#[test]
fn consensus_and_economic_sources_do_not_declare_floating_point_types() {
    fn inspect(directory: &Path) {
        for entry in fs::read_dir(directory).expect("consensus source directory must be readable") {
            let path = entry.expect("source entry must be readable").path();
            if path.is_dir() {
                inspect(&path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path).expect("Rust source must be readable");
                for token in source
                    .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                {
                    assert!(
                        token != "f32" && token != "f64",
                        "floating-point type `{token}` is prohibited in {}",
                        path.display()
                    );
                }
            }
        }
    }

    let root = workspace_root();
    for source in [
        "crates/core/src",
        "crates/mechanisms/src",
        "crates/chain/src",
    ] {
        inspect(&root.join(source));
    }
}

#[test]
fn consensus_sources_do_not_link_or_invoke_host_nondeterminism_capabilities() {
    fn inspect(directory: &Path, forbidden: &[&str]) {
        for entry in fs::read_dir(directory).expect("consensus source directory must be readable") {
            let path = entry.expect("source entry must be readable").path();
            if path.is_dir() {
                inspect(&path, forbidden);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path).expect("Rust source must be readable");
                for capability in forbidden {
                    assert!(
                        !source.contains(capability),
                        "forbidden host capability `{capability}` appears in {}",
                        path.display()
                    );
                }
            }
        }
    }

    let forbidden = [
        "std::process::Command",
        "std::process::Stdio",
        "std::env::",
        "reqwest::",
        "ureq::",
        "libgit2",
        "git2::",
        "pulldown_cmark",
        "comrak::",
        "openai",
        "anthropic",
        "Local::now",
        "OffsetDateTime::now_local",
        "Command::new(\"sh\")",
        "Command::new(\"bash\")",
        "Command::new(\"powershell\")",
    ];
    let root = workspace_root();
    for source in [
        "crates/core/src",
        "crates/mechanisms/src",
        "crates/chain/src/application",
        "crates/chain/src/engine",
        "crates/chain/src/mempool",
        "crates/chain/src/persistence",
    ] {
        inspect(&root.join(source), &forbidden);
    }

    for manifest in ["crates/core/Cargo.toml", "crates/mechanisms/Cargo.toml"] {
        let contents = fs::read_to_string(root.join(manifest)).expect("manifest must be readable");
        for dependency in [
            "reqwest",
            "ureq",
            "git2",
            "pulldown-cmark",
            "comrak",
            "openai",
            "anthropic",
        ] {
            assert!(
                !contents.contains(dependency),
                "consensus manifest {manifest} contains prohibited dependency {dependency}"
            );
        }
    }
}
