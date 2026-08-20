use std::{collections::BTreeMap, fs, path::PathBuf, str::FromStr as _};

use rachet_lab::{
    experiment::RunId,
    fixtures::{FixtureSetKind, IntegrityHash},
    simulator::LaboratoryMechanism,
    smoke::{SmokeOrchestrationConfig, orchestrate_smoke},
    workflow::{
        ExploitPromotion, RunReference, WorkflowError, audit, capture_run, compare,
        exercise_fixture_set, promote_exploit, replay, replay_exploit,
    },
};
use serde::Serialize;
use serde_json::{Value, json};

const USAGE: &str = "rcht-lab [--json] <command> [options]\n\n\
commands:\n\
  smoke --experiment DIR --public-fixtures DIR --private-fixtures DIR --repositories DIR --operators FILE [--seed N]\n\
  calibrate [--public-fixtures DIR --repositories DIR] [--seed N] [--blocks N]\n\
  run --experiment DIR --run-id ID [--mechanism m00|m01] [--seed N] [--blocks N]\n\
  replay --experiment DIR --run-id ID\n\
  compare --left-experiment DIR --left-run-id ID --right-experiment DIR --right-run-id ID\n\
  audit --experiment DIR --run-id ID\n\
  exploit promote --experiment DIR --run-id ID --exploits-root DIR --exploit-id ID --name NAME\n\
  exploit replay --exploit DIR\n";

pub struct Invocation {
    pub json: bool,
    pub outcome: Result<Success, CliError>,
}

#[derive(Debug)]
pub struct Success {
    pub command: &'static str,
    pub result: Value,
}

#[derive(Debug)]
pub struct CliError {
    pub code: &'static str,
    pub message: String,
    pub details: Value,
    pub exit_code: u8,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: "CLI_USAGE_INVALID",
            message: message.into(),
            details: json!({"usage": USAGE}),
            exit_code: 2,
        }
    }

    fn workflow(error: WorkflowError) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
            details: json!({}),
            exit_code: 1,
        }
    }
}

pub fn invoke(raw_args: Vec<String>) -> Invocation {
    let json = raw_args.iter().any(|argument| argument == "--json");
    let args = raw_args
        .into_iter()
        .filter(|argument| argument != "--json")
        .collect();
    Invocation {
        json,
        outcome: dispatch(args),
    }
}

pub fn render(invocation: &Invocation) -> String {
    match &invocation.outcome {
        Ok(success) if invocation.json => serde_json::to_string(&json!({
            "ok": true,
            "command": success.command,
            "result": success.result,
        }))
        .expect("CLI success envelope is JSON-serializable"),
        Ok(success) => format!(
            "{}: ok\n{}",
            success.command,
            serde_json::to_string_pretty(&success.result)
                .expect("CLI success result is JSON-serializable")
        ),
        Err(error) if invocation.json => serde_json::to_string(&json!({
            "error": {
                "code": error.code,
                "message": error.message,
                "details": error.details,
            }
        }))
        .expect("CLI error envelope is JSON-serializable"),
        Err(error) => format!("{}: {}", error.code, error.message),
    }
}

fn dispatch(mut args: Vec<String>) -> Result<Success, CliError> {
    if args.is_empty() {
        return Err(CliError::usage("a command is required"));
    }
    if matches!(args[0].as_str(), "help" | "-h" | "--help") {
        return Ok(Success {
            command: "help",
            result: json!({"usage": USAGE}),
        });
    }
    let command = args.remove(0);
    match command.as_str() {
        "smoke" => smoke_command(args),
        "calibrate" => fixture_command("calibrate", FixtureSetKind::Calibration, args),
        "run" => run_command(args),
        "replay" => replay_command(args),
        "compare" => compare_command(args),
        "audit" => audit_command(args),
        "exploit" => exploit_command(args),
        _ => Err(CliError::usage(format!("unknown command {command:?}"))),
    }
}

fn smoke_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let experiment_root = options.required_path("experiment")?;
    let public_fixture_root = options.required_path("public-fixtures")?;
    let private_fixture_root = options.required_path("private-fixtures")?;
    let repository_root = options.required_path("repositories")?;
    let operator_manifest = options.required_path("operators")?;
    let seed = options.optional_parse("seed", 1_u64)?;
    options.finish()?;
    let commitment_path = public_fixture_root.join("private-manifest.sha256");
    let commitment = fs::read_to_string(&commitment_path).map_err(|error| CliError {
        code: "LAB_FIXTURE_INVALID",
        message: format!(
            "cannot read private manifest commitment {}: {error}",
            commitment_path.display()
        ),
        details: json!({}),
        exit_code: 1,
    })?;
    let expected_private_manifest_hash = commitment
        .trim_end_matches(['\r', '\n'])
        .parse::<IntegrityHash>()
        .map_err(|error| CliError {
            code: "LAB_FIXTURE_INVALID",
            message: format!("invalid private manifest commitment: {error}"),
            details: json!({}),
            exit_code: 1,
        })?;
    let report = orchestrate_smoke(&SmokeOrchestrationConfig {
        experiment_root,
        public_fixture_root,
        private_fixture_root,
        repository_root,
        operator_manifest,
        expected_private_manifest_hash,
        seed,
    })
    .map_err(CliError::workflow)?;
    success("smoke", &report)
}

fn fixture_command(
    command: &'static str,
    fixture_set: FixtureSetKind,
    args: Vec<String>,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let public = options.optional_path("public-fixtures")?;
    let repositories = options.optional_path("repositories")?;
    let seed = options.optional_parse("seed", 1_u64)?;
    let blocks = options.optional_parse("blocks", 1_usize)?;
    options.finish()?;
    let report = exercise_fixture_set(
        fixture_set,
        public.as_deref(),
        repositories.as_deref(),
        seed,
        blocks,
    )
    .map_err(CliError::workflow)?;
    success(command, &report)
}

fn run_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let reference = reference(&mut options, "experiment", "run-id")?;
    let mechanism = match options
        .optional("mechanism")
        .unwrap_or_else(|| "m00".to_owned())
        .as_str()
    {
        "m00" | "m00_record_only" => LaboratoryMechanism::M00RecordOnly,
        "m01" | "m01_naive_reputation" => LaboratoryMechanism::M01NaiveReputation,
        value => {
            return Err(CliError::usage(format!(
                "invalid --mechanism {value:?}; expected m00 or m01"
            )));
        }
    };
    let seed = options.optional_parse("seed", 1_u64)?;
    let blocks = options.optional_parse("blocks", 1_usize)?;
    options.finish()?;
    let report = capture_run(&reference, mechanism, seed, blocks).map_err(CliError::workflow)?;
    success("run", &report)
}

fn replay_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let reference = reference(&mut options, "experiment", "run-id")?;
    options.finish()?;
    let report = replay(&reference).map_err(CliError::workflow)?;
    success("replay", &report)
}

fn compare_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let left = reference(&mut options, "left-experiment", "left-run-id")?;
    let right = reference(&mut options, "right-experiment", "right-run-id")?;
    options.finish()?;
    let report = compare(&left, &right).map_err(CliError::workflow)?;
    success("compare", &report)
}

fn audit_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let reference = reference(&mut options, "experiment", "run-id")?;
    options.finish()?;
    let report = audit(&reference).map_err(CliError::workflow)?;
    success("audit", &report)
}

fn exploit_command(mut args: Vec<String>) -> Result<Success, CliError> {
    if args.is_empty() {
        return Err(CliError::usage("an exploit subcommand is required"));
    }
    let subcommand = args.remove(0);
    match subcommand.as_str() {
        "promote" => promote_command(args),
        "replay" => exploit_replay_command(args),
        _ => Err(CliError::usage(format!(
            "unknown exploit subcommand {subcommand:?}"
        ))),
    }
}

fn promote_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let source = reference(&mut options, "experiment", "run-id")?;
    let request = ExploitPromotion {
        source,
        exploits_root: options.required_path("exploits-root")?,
        exploit_id: options.required("exploit-id")?,
        name: options.required("name")?,
        operator_manifest: options.optional_path("operator-manifest")?,
        root_cause: options.optional_path("root-cause")?,
    };
    options.finish()?;
    let report = promote_exploit(&request).map_err(CliError::workflow)?;
    success("exploit promote", &report)
}

fn exploit_replay_command(args: Vec<String>) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let exploit = options.required_path("exploit")?;
    options.finish()?;
    let report = replay_exploit(&exploit).map_err(CliError::workflow)?;
    success("exploit replay", &report)
}

fn reference(
    options: &mut Options,
    experiment_key: &'static str,
    run_key: &'static str,
) -> Result<RunReference, CliError> {
    let experiment_root = options.required_path(experiment_key)?;
    let run_text = options.required(run_key)?;
    let run_id = RunId::from_str(&run_text)
        .map_err(|error| CliError::usage(format!("invalid --{run_key}: {error}")))?;
    Ok(RunReference {
        experiment_root,
        run_id,
    })
}

fn success<T: Serialize>(command: &'static str, report: &T) -> Result<Success, CliError> {
    let result = serde_json::to_value(report).map_err(|error| CliError {
        code: "CLI_JSON_FAILED",
        message: format!("cannot encode command result: {error}"),
        details: json!({}),
        exit_code: 1,
    })?;
    Ok(Success { command, result })
}

struct Options(BTreeMap<String, String>);

impl Options {
    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        let mut values = BTreeMap::new();
        let mut arguments = args.into_iter();
        while let Some(flag) = arguments.next() {
            let key = flag
                .strip_prefix("--")
                .filter(|key| !key.is_empty())
                .ok_or_else(|| {
                    CliError::usage(format!("unexpected positional argument {flag:?}"))
                })?;
            let value = arguments
                .next()
                .ok_or_else(|| CliError::usage(format!("--{key} requires a value")))?;
            if value.starts_with("--") {
                return Err(CliError::usage(format!("--{key} requires a value")));
            }
            if values.insert(key.to_owned(), value).is_some() {
                return Err(CliError::usage(format!(
                    "--{key} was supplied more than once"
                )));
            }
        }
        Ok(Self(values))
    }

    fn required(&mut self, key: &'static str) -> Result<String, CliError> {
        self.0
            .remove(key)
            .ok_or_else(|| CliError::usage(format!("--{key} is required")))
    }

    fn optional(&mut self, key: &'static str) -> Option<String> {
        self.0.remove(key)
    }

    fn required_path(&mut self, key: &'static str) -> Result<PathBuf, CliError> {
        self.required(key).map(PathBuf::from)
    }

    fn optional_path(&mut self, key: &'static str) -> Result<Option<PathBuf>, CliError> {
        Ok(self.optional(key).map(PathBuf::from))
    }

    fn optional_parse<T>(&mut self, key: &'static str, default: T) -> Result<T, CliError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.optional(key) {
            Some(value) => value
                .parse()
                .map_err(|error| CliError::usage(format!("invalid --{key} {value:?}: {error}"))),
            None => Ok(default),
        }
    }

    fn finish(self) -> Result<(), CliError> {
        if let Some(key) = self.0.keys().next() {
            return Err(CliError::usage(format!("unknown option --{key}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn every_command_has_machine_readable_success_and_failure() {
        let temp = TempDirectory::new();
        let experiment = temp.path().join("experiment");
        let exploits = temp.path().join("exploits");
        let run_id = "43".repeat(32);
        fs::create_dir_all(experiment.join("runs").join(&run_id)).unwrap();
        fs::create_dir_all(experiment.join("seeds")).unwrap();
        fs::create_dir_all(experiment.join("operators")).unwrap();
        fs::write(
            experiment.join("operators/operator-001.toml"),
            b"policy = \"smoke\"\n",
        )
        .unwrap();
        fs::write(
            experiment.join("mechanism-set.toml"),
            b"mechanisms = [\"M00@1.0.0\"]\n",
        )
        .unwrap();

        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert_success(&[
            "smoke",
            "--experiment",
            path(&experiment),
            "--public-fixtures",
            path(&workspace.join("fixtures/jobs-public/smoke")),
            "--private-fixtures",
            path(&workspace.join("fixtures/ground-truth-private/smoke")),
            "--repositories",
            path(&workspace.join("fixtures/repositories")),
            "--operators",
            path(&workspace.join("experiments/H-REP-001/operators/fixed-heuristics.json")),
            "--seed",
            "9201",
        ]);
        assert_success(&["calibrate", "--blocks", "1"]);
        assert_success(&[
            "run",
            "--experiment",
            path(&experiment),
            "--run-id",
            &run_id,
            "--mechanism",
            "m00",
            "--blocks",
            "2",
        ]);
        assert_success(&[
            "replay",
            "--experiment",
            path(&experiment),
            "--run-id",
            &run_id,
        ]);
        assert_success(&[
            "compare",
            "--left-experiment",
            path(&experiment),
            "--left-run-id",
            &run_id,
            "--right-experiment",
            path(&experiment),
            "--right-run-id",
            &run_id,
        ]);
        assert_success(&[
            "audit",
            "--experiment",
            path(&experiment),
            "--run-id",
            &run_id,
        ]);
        assert_success(&[
            "exploit",
            "promote",
            "--experiment",
            path(&experiment),
            "--run-id",
            &run_id,
            "--exploits-root",
            path(&exploits),
            "--exploit-id",
            "REP-043",
            "--name",
            "smoke exploit",
        ]);
        assert_success(&[
            "exploit",
            "replay",
            "--exploit",
            path(&exploits.join("REP-043")),
        ]);

        for failure in [
            vec!["smoke"],
            vec!["calibrate", "--blocks", "0"],
            vec!["run"],
            vec!["replay"],
            vec!["compare"],
            vec!["audit"],
            vec!["exploit", "promote"],
            vec!["exploit", "replay"],
        ] {
            assert_failure(&failure);
        }
    }

    #[test]
    fn json_errors_have_the_stable_section_48_shape() {
        let invocation = invoke(vec!["--json".to_owned(), "unknown".to_owned()]);
        let value: Value = serde_json::from_str(&render(&invocation)).unwrap();
        assert_eq!(value["error"]["code"], "CLI_USAGE_INVALID");
        assert!(value["error"]["message"].is_string());
        assert!(value["error"]["details"].is_object());
    }

    fn assert_success(args: &[&str]) {
        let mut owned = args
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        owned.push("--json".to_owned());
        let invocation = invoke(owned);
        assert!(invocation.outcome.is_ok(), "{}", render(&invocation));
        let value: Value = serde_json::from_str(&render(&invocation)).unwrap();
        assert_eq!(value["ok"], true);
        assert!(value["result"].is_object());
    }

    fn assert_failure(args: &[&str]) {
        let mut owned = args
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        owned.push("--json".to_owned());
        let invocation = invoke(owned);
        assert!(invocation.outcome.is_err());
        let value: Value = serde_json::from_str(&render(&invocation)).unwrap();
        assert!(value["error"]["code"].is_string());
        assert!(value["error"]["message"].is_string());
        assert!(value["error"]["details"].is_object());
    }

    fn path(value: &Path) -> &str {
        value.to_str().unwrap()
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("rachet-lab-cli-{}-{sequence}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
