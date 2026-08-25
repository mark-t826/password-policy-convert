use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

use password_policy_convert::policy;

const USAGE: &str = "usage: password-policy-convert <to-rules|to-query|to-json> [file]\n\
                      reads from stdin if no file is given\n\
                      to-rules reads the query-string format; to-query and to-json read the rules format";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let Some(direction) = args.get(1).map(String::as_str) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let input = match args.get(2) {
        Some(path) => match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) => {
                eprintln!("failed to read {path}: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            let mut buf = String::new();
            if let Err(err) = io::stdin().read_to_string(&mut buf) {
                eprintln!("failed to read stdin: {err}");
                return ExitCode::FAILURE;
            }
            buf
        }
    };

    let result = match direction {
        "to-rules" => policy::convert_query_to_rules(&input),
        "to-query" => policy::convert_rules_to_query(&input),
        "to-json" => policy::convert_rules_to_json(&input),
        other => {
            eprintln!("unknown direction '{other}'\n{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("conversion failed: {err}");
            ExitCode::FAILURE
        }
    }
}
