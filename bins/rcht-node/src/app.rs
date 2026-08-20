use rachet_chain::{
    config::{MAX_NODE_CONFIG_BYTES, NodeConfig, ValidatedNodeConfig},
    engine::{LiveNodeError, live_runtime_config, run_live_node},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};

const USAGE: &str = "rcht-node [--json] <command> [options]\n\n\
commands:\n\
  init [--config PATH] [--node-index 0..3] [--force]\n\
  run [--config PATH]\n\
  status [--config PATH]\n\
  inspect-config [--config PATH]\n\n\
RCHT_NODE_CONFIG is captured once at process startup and is used only when\n\
--config is absent. The default is rcht-node.json.\n";
const CONFIG_ENVIRONMENT_KEY: &str = "RCHT_NODE_CONFIG";
const RPC_STATUS_TIMEOUT: Duration = Duration::from_millis(200);

/// Mutable process inputs captured before command parsing or node construction.
#[derive(Clone, Debug)]
pub struct StartupEnvironment {
    default_config: PathBuf,
}

impl StartupEnvironment {
    pub fn capture() -> Self {
        let default_config = std::env::var_os(CONFIG_ENVIRONMENT_KEY)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("rcht-node.json"));
        Self { default_config }
    }

    #[cfg(test)]
    fn fixed(path: PathBuf) -> Self {
        Self {
            default_config: path,
        }
    }
}

pub struct Invocation {
    pub json: bool,
    pub outcome: Result<Success, CliError>,
}

#[derive(Debug)]
pub struct Success {
    command: &'static str,
    result: Value,
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

    fn io(code: &'static str, operation: &str, path: &Path, error: impl std::fmt::Display) -> Self {
        Self {
            code,
            message: format!("cannot {operation} {}: {error}", path.display()),
            details: json!({"path": path}),
            exit_code: 1,
        }
    }

    fn config(path: &Path, error: rachet_chain::config::NodeConfigError) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
            details: json!({"path": path}),
            exit_code: 1,
        }
    }

    fn run(error: LiveNodeError) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
            details: json!({}),
            exit_code: 1,
        }
    }
}

/// Injection boundary used to test the blocking `run` command without replacing
/// any Commonware component in the production path.
pub trait NodeLauncher {
    fn launch(&mut self, config: ValidatedNodeConfig) -> Result<(), LiveNodeError>;
}

pub struct SystemNodeLauncher;

impl NodeLauncher for SystemNodeLauncher {
    fn launch(&mut self, config: ValidatedNodeConfig) -> Result<(), LiveNodeError> {
        let storage = config.storage_directory().to_path_buf();
        run_live_node(
            live_runtime_config(storage),
            config.into_live(),
            std::future::pending::<()>(),
        )
    }
}

pub fn invoke(
    raw_args: Vec<String>,
    startup: &StartupEnvironment,
    launcher: &mut dyn NodeLauncher,
) -> Invocation {
    let json = raw_args.iter().any(|argument| argument == "--json");
    let args = raw_args
        .into_iter()
        .filter(|argument| argument != "--json")
        .collect();
    Invocation {
        json,
        outcome: dispatch(args, startup, launcher),
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

fn dispatch(
    mut args: Vec<String>,
    startup: &StartupEnvironment,
    launcher: &mut dyn NodeLauncher,
) -> Result<Success, CliError> {
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
        "init" => init_command(args, startup),
        "run" => run_command(args, startup, launcher),
        "status" => status_command(args, startup),
        "inspect-config" => inspect_command(args, startup),
        _ => Err(CliError::usage(format!("unknown command {command:?}"))),
    }
}

fn init_command(args: Vec<String>, startup: &StartupEnvironment) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let config_path = options.config_path(startup);
    let node_index = options.optional_parse("node-index", 0_usize)?;
    let force = options.flag("force");
    options.finish()?;

    if config_path.exists() && !force {
        return Err(CliError {
            code: "NODE_CONFIG_EXISTS",
            message: format!(
                "node configuration {} already exists; use --force to replace it",
                config_path.display()
            ),
            details: json!({"path": config_path}),
            exit_code: 1,
        });
    }
    let parent = config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty());
    let storage = parent
        .unwrap_or_else(|| Path::new("."))
        .join("data")
        .join(format!("node-{node_index}"));
    let config = NodeConfig::devnet(node_index, storage)
        .map_err(|error| CliError::config(&config_path, error))?;
    let bytes = config
        .to_pretty_json()
        .map_err(|error| CliError::config(&config_path, error))?;

    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .map_err(|error| CliError::io("NODE_CONFIG_WRITE_FAILED", "create", parent, error))?;
    }
    write_private_config(&config_path, &bytes, force)?;
    Ok(Success {
        command: "init",
        result: json!({
            "config_path": config_path,
            "node": config.node_name(),
            "node_index": config.node_index(),
            "storage_directory": config.storage_directory(),
            "rpc_address": config.rpc_address(),
            "committee_size": 4,
            "development_keys": true,
        }),
    })
}

fn run_command(
    args: Vec<String>,
    startup: &StartupEnvironment,
    launcher: &mut dyn NodeLauncher,
) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let config_path = options.config_path(startup);
    options.finish()?;
    let validated = load_validated(&config_path)?;
    let summary = validated.summary();
    // No runtime config, storage handle, socket, or actor exists before the
    // complete document has reached this point.
    launcher.launch(validated).map_err(CliError::run)?;
    Ok(Success {
        command: "run",
        result: json!({"state": "stopped", "config": summary}),
    })
}

fn status_command(args: Vec<String>, startup: &StartupEnvironment) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let config_path = options.config_path(startup);
    options.finish()?;
    let validated = load_validated(&config_path)?;
    let reachable = rpc_reachable(validated.rpc_listen());
    Ok(Success {
        command: "status",
        result: json!({
            "state": if reachable { "running" } else { "stopped" },
            "rpc_reachable": reachable,
            "config_path": config_path,
            "config": validated.summary(),
        }),
    })
}

fn inspect_command(args: Vec<String>, startup: &StartupEnvironment) -> Result<Success, CliError> {
    let mut options = Options::parse(args)?;
    let config_path = options.config_path(startup);
    options.finish()?;
    let validated = load_validated(&config_path)?;
    Ok(Success {
        command: "inspect-config",
        result: json!({
            "valid": true,
            "config_path": config_path,
            "config": validated.source().redacted_value(),
        }),
    })
}

fn load_validated(path: &Path) -> Result<ValidatedNodeConfig, CliError> {
    let bytes = read_bounded(path)?;
    NodeConfig::parse(&bytes)
        .and_then(NodeConfig::validate)
        .map_err(|error| CliError::config(path, error))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, CliError> {
    let file = File::open(path).map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::NotFound {
            "NODE_CONFIG_NOT_FOUND"
        } else {
            "NODE_CONFIG_READ_FAILED"
        };
        CliError::io(code, "read", path, error)
    })?;
    let maximum = u64::try_from(MAX_NODE_CONFIG_BYTES).expect("config bound fits u64") + 1;
    let mut bytes = Vec::with_capacity(MAX_NODE_CONFIG_BYTES.min(8 * 1024));
    file.take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::io("NODE_CONFIG_READ_FAILED", "read", path, error))?;
    if bytes.len() > MAX_NODE_CONFIG_BYTES {
        return Err(CliError {
            code: "NODE_CONFIG_TOO_LARGE",
            message: format!("node configuration is larger than {MAX_NODE_CONFIG_BYTES} bytes"),
            details: json!({"path": path}),
            exit_code: 1,
        });
    }
    Ok(bytes)
}

fn write_private_config(path: &Path, bytes: &[u8], force: bool) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| CliError::io("NODE_CONFIG_WRITE_FAILED", "write", path, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| CliError::io("NODE_CONFIG_WRITE_FAILED", "write", path, error))
}

fn rpc_reachable(address: SocketAddr) -> bool {
    TcpStream::connect_timeout(&address, RPC_STATUS_TIMEOUT).is_ok()
}

struct Options {
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}

impl Options {
    fn parse(args: Vec<String>) -> Result<Self, CliError> {
        let mut values = BTreeMap::new();
        let mut flags = BTreeSet::new();
        let mut arguments = args.into_iter().peekable();
        while let Some(flag) = arguments.next() {
            let key = flag
                .strip_prefix("--")
                .filter(|key| !key.is_empty())
                .ok_or_else(|| {
                    CliError::usage(format!("unexpected positional argument {flag:?}"))
                })?;
            if key == "force" {
                if !flags.insert(key.to_owned()) {
                    return Err(CliError::usage("--force was supplied more than once"));
                }
                continue;
            }
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
        Ok(Self { values, flags })
    }

    fn config_path(&mut self, startup: &StartupEnvironment) -> PathBuf {
        self.values
            .remove("config")
            .map(PathBuf::from)
            .unwrap_or_else(|| startup.default_config.clone())
    }

    fn optional_parse<T>(&mut self, key: &'static str, default: T) -> Result<T, CliError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.values.remove(key) {
            Some(value) => value
                .parse()
                .map_err(|error| CliError::usage(format!("invalid --{key} {value:?}: {error}"))),
            None => Ok(default),
        }
    }

    fn flag(&mut self, key: &'static str) -> bool {
        self.flags.remove(key)
    }

    fn finish(self) -> Result<(), CliError> {
        if let Some(key) = self.values.keys().next() {
            return Err(CliError::usage(format!("unknown option --{key}")));
        }
        if let Some(key) = self.flags.iter().next() {
            return Err(CliError::usage(format!("unknown flag --{key}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct FakeLauncher {
        launches: usize,
    }

    impl NodeLauncher for FakeLauncher {
        fn launch(&mut self, _: ValidatedNodeConfig) -> Result<(), LiveNodeError> {
            self.launches += 1;
            Ok(())
        }
    }

    #[test]
    fn every_node_command_has_a_json_contract_and_inspection_redacts_keys() {
        let temp = TempDirectory::new();
        let path = temp.path().join("node.json");
        let startup = StartupEnvironment::fixed(path.clone());
        let mut launcher = FakeLauncher { launches: 0 };

        let init = invoke(
            vec![
                "--json".into(),
                "init".into(),
                "--node-index".into(),
                "1".into(),
            ],
            &startup,
            &mut launcher,
        );
        assert_json_success(&init, "init");
        let raw = fs::read_to_string(&path).unwrap();
        let private_key =
            serde_json::from_str::<Value>(&raw).unwrap()["node"]["consensus_private_key"]
                .as_str()
                .unwrap()
                .to_owned();

        let inspect = invoke(
            vec!["inspect-config".into(), "--json".into()],
            &startup,
            &mut launcher,
        );
        let inspected = assert_json_success(&inspect, "inspect-config");
        assert_eq!(
            inspected["result"]["config"]["node"]["consensus_private_key"],
            "[REDACTED]"
        );
        assert!(!render(&inspect).contains(&private_key));

        let status = invoke(
            vec!["status".into(), "--json".into()],
            &startup,
            &mut launcher,
        );
        assert_eq!(
            assert_json_success(&status, "status")["result"]["state"],
            "stopped"
        );

        let run = invoke(vec!["run".into(), "--json".into()], &startup, &mut launcher);
        assert_json_success(&run, "run");
        assert_eq!(launcher.launches, 1);
    }

    #[test]
    fn invalid_run_config_fails_before_launcher_or_storage_mutation() {
        let temp = TempDirectory::new();
        let path = temp.path().join("invalid.json");
        let storage = temp.path().join("must-not-exist");
        let mut value =
            serde_json::to_value(NodeConfig::devnet(0, storage.clone()).expect("valid fixture"))
                .unwrap();
        value["committee"].as_array_mut().unwrap().pop();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let startup = StartupEnvironment::fixed(path);
        let mut launcher = FakeLauncher { launches: 0 };
        let invocation = invoke(vec!["run".into(), "--json".into()], &startup, &mut launcher);
        let error: Value = serde_json::from_str(&render(&invocation)).unwrap();
        assert_eq!(error["error"]["code"], "NODE_CONFIG_COMMITTEE_INVALID");
        assert_eq!(launcher.launches, 0);
        assert!(!storage.exists());
    }

    #[test]
    fn json_usage_error_uses_stable_envelope() {
        let temp = TempDirectory::new();
        let startup = StartupEnvironment::fixed(temp.path().join("node.json"));
        let mut launcher = FakeLauncher { launches: 0 };
        let invocation = invoke(
            vec!["--json".into(), "unknown".into()],
            &startup,
            &mut launcher,
        );
        let value: Value = serde_json::from_str(&render(&invocation)).unwrap();
        assert_eq!(value["error"]["code"], "CLI_USAGE_INVALID");
    }

    fn assert_json_success(invocation: &Invocation, command: &str) -> Value {
        let value: Value = serde_json::from_str(&render(invocation)).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["command"], command);
        value
    }

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rachet-node-cli-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
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
