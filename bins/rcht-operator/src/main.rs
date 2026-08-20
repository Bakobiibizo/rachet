mod app;

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let invocation = app::invoke(env::args().skip(1).collect());
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
