mod app;

use app::{StartupEnvironment, SystemNodeLauncher};
use std::{env, process::ExitCode};

fn main() -> ExitCode {
    // Capture mutable process configuration once. The consensus runtime receives
    // only the validated owned configuration built from this snapshot.
    let startup = StartupEnvironment::capture();
    let mut launcher = SystemNodeLauncher;
    let invocation = app::invoke(env::args().skip(1).collect(), &startup, &mut launcher);
    let output = app::render(&invocation);
    match &invocation.outcome {
        Ok(_) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{output}");
            ExitCode::from(error.exit_code)
        }
    }
}
