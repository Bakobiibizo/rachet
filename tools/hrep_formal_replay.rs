use std::{env, fs, path::PathBuf, str::FromStr as _};

use rachet_lab::{experiment::RunId, replay::replay_run};
use serde::Deserialize;

#[derive(Deserialize)]
struct Report {
    runs: Vec<Run>,
}

#[derive(Deserialize)]
struct Run {
    run_id: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: hrep_formal_replay <experiment-root> <formal-execution.json>".into());
    }
    let experiment = PathBuf::from(&args[1]);
    let report: Report = serde_json::from_slice(&fs::read(&args[2])?)?;
    if report.runs.len() != 10 {
        return Err("expected ten formal runs".into());
    }
    let mut blocks = 0;
    for run in report.runs {
        let id = RunId::from_str(&run.run_id)?;
        let replay = replay_run(&experiment, id)?;
        if replay.model_calls != 0
            || replay.terminal_error.is_some()
            || replay.blocks_replayed != 103
        {
            return Err(format!("replay mismatch: {}", run.run_id).into());
        }
        blocks += replay.blocks_replayed;
        println!(
            "{} blocks={} model_calls=0 exact=true",
            run.run_id, replay.blocks_replayed
        );
    }
    println!("runs=10 blocks={} exact=true", blocks);
    Ok(())
}
