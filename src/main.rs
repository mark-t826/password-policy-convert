use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::ExitCode;

use password_policy_convert::policy;

const USAGE: &str = "usage: password-policy-convert <direction> [file]\n\
                      reads from stdin if no file is given\n\
                      directions: to-rules (query-string -> rules), to-query and to-json (rules -> ...),\n\
                      from-json-to-rules and from-json-to-query (json -> ...),\n\
                      from-pwquality-to-rules, from-pwquality-to-query and from-pwquality-to-json\n\
                      (pwquality.conf -> ...),\n\
                      validate (rules -> list of contradictory-rule warnings)\n\
                      check <password> [rules-file] (rules -> list of ways the password fails the policy)";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let Some(direction) = args.get(1).map(String::as_str) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };

    if direction == "check" {
        let Some(password) = args.get(2) else {
            eprintln!("check requires a password argument\n{USAGE}");
            return ExitCode::FAILURE;
        };
        let input = match read_input(args.get(3)) {
            Ok(contents) => contents,
            Err(code) => return code,
        };

        return match policy::parse_rules(&input) {
            Ok(parsed) => {
                let violations = policy::check_password(&parsed, password);
                if violations.is_empty() {
                    println!("password satisfies the policy");
                } else {
                    for violation in &violations {
                        println!("{violation}");
                    }
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("conversion failed: {err}");
                ExitCode::FAILURE
            }
        };
    }

    let input = match read_input(args.get(2)) {
        Ok(contents) => contents,
        Err(code) => return code,
    };

    run(direction, &input)
}

fn read_input(path: Option<&String>) -> Result<String, ExitCode> {
    match path {
        Some(path) => fs::read_to_string(path).map_err(|err| {
            eprintln!("failed to read {path}: {err}");
            ExitCode::FAILURE
        }),
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf).map_err(|err| {
                eprintln!("failed to read stdin: {err}");
                ExitCode::FAILURE
            })?;
            Ok(buf)
        }
    }
}

fn run(direction: &str, input: &str) -> ExitCode {
    if direction == "validate" {
        return match policy::parse_rules(input) {
            Ok(parsed) => {
                let warnings = policy::validate(&parsed);
                if warnings.is_empty() {
                    println!("no warnings");
                } else {
                    for warning in &warnings {
                        println!("{warning}");
                    }
                }
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("conversion failed: {err}");
                ExitCode::FAILURE
            }
        };
    }

    let result = match direction {
        "to-rules" => policy::convert_query_to_rules(input),
        "to-query" => policy::convert_rules_to_query(input),
        "to-json" => policy::convert_rules_to_json(input),
        "from-json-to-rules" => policy::convert_json_to_rules(input),
        "from-json-to-query" => policy::convert_json_to_query(input),
        "from-pwquality-to-rules" => policy::convert_pwquality_to_rules(input),
        "from-pwquality-to-query" => policy::convert_pwquality_to_query(input),
        "from-pwquality-to-json" => policy::convert_pwquality_to_json(input),
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
