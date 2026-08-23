//! Two ways of writing down a password composition policy show up in the
//! systems I deal with: a line-based rules file (one directive per line,
//! `key=value`) and a single-line query-string format left over from an
//! older web form validator (`key=value&key=value`). Neither can read the
//! other's file, so anyone migrating a policy between them has been doing
//! it by hand and periodically getting a field wrong.
//!
//! Everything here goes through `PasswordPolicy` as the shared
//! representation, so the two formats never have to know about each other
//! directly.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub max_length: Option<u32>,
    pub require_upper: bool,
    pub require_lower: bool,
    pub require_digit: bool,
    pub require_symbol: bool,
    pub max_repeated_chars: Option<u32>,
    pub min_unique_chars: Option<u32>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicy {
            min_length: 8,
            max_length: None,
            require_upper: false,
            require_lower: false,
            require_digit: false,
            require_symbol: false,
            max_repeated_chars: None,
            min_unique_chars: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    UnknownKey(String),
    MissingValue(String),
    InvalidValue { key: String, value: String },
    MissingRequiredField(&'static str),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::UnknownKey(key) => write!(f, "unknown key '{key}'"),
            PolicyError::MissingValue(key) => write!(f, "key '{key}' has no value"),
            PolicyError::InvalidValue { key, value } => {
                write!(f, "invalid value '{value}' for key '{key}'")
            }
            PolicyError::MissingRequiredField(name) => {
                write!(f, "missing required field '{name}'")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

fn parse_bool(key: &str, value: &str) -> Result<bool, PolicyError> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        other => Err(PolicyError::InvalidValue {
            key: key.to_string(),
            value: other.to_string(),
        }),
    }
}

fn parse_u32(key: &str, value: &str) -> Result<u32, PolicyError> {
    value.parse::<u32>().map_err(|_| PolicyError::InvalidValue {
        key: key.to_string(),
        value: value.to_string(),
    })
}

/// Parses the line-based rules format:
///
/// ```text
/// min_length=12
/// max_length=64
/// require_upper=true
/// require_lower=true
/// require_digit=true
/// require_symbol=false
/// max_repeated_chars=3
/// min_unique_chars=6
/// ```
///
/// Blank lines and lines starting with `#` are ignored.
pub fn parse_rules(input: &str) -> Result<PasswordPolicy, PolicyError> {
    let mut policy = PasswordPolicy::default();
    let mut min_length_seen = false;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = split_key_value(line, '=')?;

        match key {
            "min_length" => {
                policy.min_length = parse_u32(key, value)?;
                min_length_seen = true;
            }
            "max_length" => policy.max_length = Some(parse_u32(key, value)?),
            "require_upper" => policy.require_upper = parse_bool(key, value)?,
            "require_lower" => policy.require_lower = parse_bool(key, value)?,
            "require_digit" => policy.require_digit = parse_bool(key, value)?,
            "require_symbol" => policy.require_symbol = parse_bool(key, value)?,
            "max_repeated_chars" => policy.max_repeated_chars = Some(parse_u32(key, value)?),
            "min_unique_chars" => policy.min_unique_chars = Some(parse_u32(key, value)?),
            other => return Err(PolicyError::UnknownKey(other.to_string())),
        }
    }

    if !min_length_seen {
        return Err(PolicyError::MissingRequiredField("min_length"));
    }

    Ok(policy)
}

/// Renders a policy back into the line-based rules format.
pub fn to_rules(policy: &PasswordPolicy) -> String {
    let mut lines = vec![
        format!("min_length={}", policy.min_length),
        format!("require_upper={}", policy.require_upper),
        format!("require_lower={}", policy.require_lower),
        format!("require_digit={}", policy.require_digit),
        format!("require_symbol={}", policy.require_symbol),
    ];

    if let Some(max_length) = policy.max_length {
        lines.insert(1, format!("max_length={max_length}"));
    }
    if let Some(max_repeated) = policy.max_repeated_chars {
        lines.push(format!("max_repeated_chars={max_repeated}"));
    }
    if let Some(min_unique) = policy.min_unique_chars {
        lines.push(format!("min_unique_chars={min_unique}"));
    }

    lines.join("\n")
}

/// Parses the query-string format used by the old form validator:
///
/// ```text
/// minLength=12&maxLength=64&upper=1&lower=1&digit=1&symbol=0&maxRepeat=3&minUnique=6
/// ```
pub fn parse_query(input: &str) -> Result<PasswordPolicy, PolicyError> {
    let mut policy = PasswordPolicy::default();
    let mut min_length_seen = false;

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PolicyError::MissingRequiredField("minLength"));
    }

    for pair in trimmed.split('&') {
        let (key, value) = split_key_value(pair, '=')?;

        match key {
            "minLength" => {
                policy.min_length = parse_u32(key, value)?;
                min_length_seen = true;
            }
            "maxLength" => policy.max_length = Some(parse_u32(key, value)?),
            "upper" => policy.require_upper = parse_bool(key, value)?,
            "lower" => policy.require_lower = parse_bool(key, value)?,
            "digit" => policy.require_digit = parse_bool(key, value)?,
            "symbol" => policy.require_symbol = parse_bool(key, value)?,
            "maxRepeat" => policy.max_repeated_chars = Some(parse_u32(key, value)?),
            "minUnique" => policy.min_unique_chars = Some(parse_u32(key, value)?),
            other => return Err(PolicyError::UnknownKey(other.to_string())),
        }
    }

    if !min_length_seen {
        return Err(PolicyError::MissingRequiredField("minLength"));
    }

    Ok(policy)
}

/// Renders a policy back into the query-string format.
pub fn to_query(policy: &PasswordPolicy) -> String {
    let mut parts = vec![format!("minLength={}", policy.min_length)];

    if let Some(max_length) = policy.max_length {
        parts.push(format!("maxLength={max_length}"));
    }

    parts.push(format!("upper={}", bool_flag(policy.require_upper)));
    parts.push(format!("lower={}", bool_flag(policy.require_lower)));
    parts.push(format!("digit={}", bool_flag(policy.require_digit)));
    parts.push(format!("symbol={}", bool_flag(policy.require_symbol)));

    if let Some(max_repeated) = policy.max_repeated_chars {
        parts.push(format!("maxRepeat={max_repeated}"));
    }
    if let Some(min_unique) = policy.min_unique_chars {
        parts.push(format!("minUnique={min_unique}"));
    }

    parts.join("&")
}

fn bool_flag(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn split_key_value(pair: &str, sep: char) -> Result<(&str, &str), PolicyError> {
    let mut parts = pair.splitn(2, sep);
    let key = parts.next().unwrap_or("").trim();
    let value = parts.next().map(str::trim);

    match value {
        Some(v) if !v.is_empty() => Ok((key, v)),
        _ => Err(PolicyError::MissingValue(key.to_string())),
    }
}

/// Convenience wrapper: rules text in, query text out.
pub fn convert_rules_to_query(input: &str) -> Result<String, PolicyError> {
    parse_rules(input).map(|policy| to_query(&policy))
}

/// Convenience wrapper: query text in, rules text out.
pub fn convert_query_to_rules(input: &str) -> Result<String, PolicyError> {
    parse_query(input).map(|policy| to_rules(&policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 12,
            max_length: Some(64),
            require_upper: true,
            require_lower: true,
            require_digit: true,
            require_symbol: false,
            max_repeated_chars: Some(3),
            min_unique_chars: Some(6),
        }
    }

    #[test]
    fn parses_full_rules_file() {
        let input = "min_length=12\nmax_length=64\nrequire_upper=true\n\
                      require_lower=true\nrequire_digit=true\nrequire_symbol=false\n\
                      max_repeated_chars=3\nmin_unique_chars=6\n";

        assert_eq!(parse_rules(input).unwrap(), sample_policy());
    }

    #[test]
    fn rules_file_ignores_blank_lines_and_comments() {
        let input = "# password policy\nmin_length=10\n\nrequire_digit=true\n";
        let policy = parse_rules(input).unwrap();
        assert_eq!(policy.min_length, 10);
        assert!(policy.require_digit);
    }

    #[test]
    fn rules_file_missing_min_length_is_an_error() {
        let err = parse_rules("require_digit=true\n").unwrap_err();
        assert_eq!(err, PolicyError::MissingRequiredField("min_length"));
    }

    #[test]
    fn rules_file_rejects_unknown_key() {
        let err = parse_rules("min_length=8\nrequire_emoji=true\n").unwrap_err();
        assert_eq!(err, PolicyError::UnknownKey("require_emoji".to_string()));
    }

    #[test]
    fn parses_full_query_string() {
        let input = "minLength=12&maxLength=64&upper=1&lower=1&digit=1&symbol=0&maxRepeat=3&minUnique=6";
        assert_eq!(parse_query(input).unwrap(), sample_policy());
    }

    #[test]
    fn query_string_missing_min_length_is_an_error() {
        let err = parse_query("upper=1&lower=1").unwrap_err();
        assert_eq!(err, PolicyError::MissingRequiredField("minLength"));
    }

    #[test]
    fn query_string_rejects_bad_bool_value() {
        let err = parse_query("minLength=8&upper=yes").unwrap_err();
        assert_eq!(
            err,
            PolicyError::InvalidValue {
                key: "upper".to_string(),
                value: "yes".to_string(),
            }
        );
    }

    #[test]
    fn round_trips_rules_through_query() {
        let policy = sample_policy();
        let as_query = to_query(&policy);
        let back = parse_query(&as_query).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn round_trips_query_through_rules() {
        let policy = sample_policy();
        let as_rules = to_rules(&policy);
        let back = parse_rules(&as_rules).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn convert_rules_to_query_matches_manual_conversion() {
        let input = "min_length=8\nrequire_digit=true\n";
        let policy = parse_rules(input).unwrap();
        assert_eq!(convert_rules_to_query(input).unwrap(), to_query(&policy));
    }

    #[test]
    fn omits_absent_optional_fields_in_both_formats() {
        let minimal = PasswordPolicy {
            min_length: 8,
            ..PasswordPolicy::default()
        };
        assert_eq!(
            to_rules(&minimal),
            "min_length=8\nrequire_upper=false\nrequire_lower=false\n\
             require_digit=false\nrequire_symbol=false"
        );
        assert_eq!(to_query(&minimal), "minLength=8&upper=0&lower=0&digit=0&symbol=0");
    }
}
