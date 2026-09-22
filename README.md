# password-policy-convert

Password composition policy formats show up in the systems I've worked on.
One is a line-based rules file:

```
min_length=12
max_length=64
require_upper=true
require_lower=true
require_digit=true
require_symbol=false
max_repeated_chars=3
min_unique_chars=6
```

The other is a query-string format left over from an older web form
validator, still used by a couple of internal services:

```
minLength=12&maxLength=64&upper=1&lower=1&digit=1&symbol=0&maxRepeat=3&minUnique=6
```

Neither side reads the other's format, so migrating a policy between them
has meant transcribing it by hand and occasionally dropping a field or
flipping a `1`/`0`. This converts between formats through a shared
`PasswordPolicy` struct, so no format needs to know about any other.

There's also a JSON format, for feeding a policy into or out of something
that expects structured input, using the same field names as the rules
file:

```
{"min_length":12,"max_length":64,"require_upper":true,"require_lower":true,"require_digit":true,"require_symbol":false,"max_repeated_chars":3,"min_unique_chars":6}
```

## Usage

```
$ cat policy.rules
min_length=12
require_upper=true
require_lower=true
require_digit=true
require_symbol=false

$ cargo run -- to-query policy.rules
minLength=12&upper=1&lower=1&digit=1&symbol=0

$ echo "minLength=10&upper=1&digit=1" | cargo run -- to-rules
min_length=10
require_upper=true
require_lower=false
require_digit=true
require_symbol=false

$ cargo run -- to-json policy.rules
{"min_length":12,"max_length":null,"require_upper":true,"require_lower":true,"require_digit":true,"require_symbol":false,"max_repeated_chars":null,"min_unique_chars":null}

$ echo '{"min_length":10,"require_upper":true}' | cargo run -- from-json-to-rules
min_length=10
require_upper=true
require_lower=false
require_digit=false
require_symbol=false
```

There's also read-only support for PAM's `pwquality.conf` syntax, since
that's the format a few of the systems I deal with actually ship their
policy in:

```
$ cat pwquality.conf
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
minclass = 4
dictcheck = 1
retry = 3

$ cargo run -- from-pwquality-to-rules pwquality.conf
min_length=12
require_upper=true
require_lower=true
require_digit=true
require_symbol=true
max_repeated_chars=3
```

Only `minlen`, `maxrepeat`, and the `dcredit`/`ucredit`/`lcredit`/`ocredit`
class-credit directives are read; everything else in the file (`minclass`,
`dictcheck`, `retry`, bare flags like `enforce_for_root`, and so on) is
ignored rather than rejected, since a real `pwquality.conf` carries plenty
of settings `PasswordPolicy` has no field for. A negative credit value
means "require at least one character of this class"; zero or positive
does not. There is no `to-pwquality` direction — going the other way would
mean inventing values for directives this library doesn't model.

If no file argument is given, input is read from stdin. Unknown keys,
missing values, and a missing `min_length`/`minLength` are reported as
errors rather than silently defaulted.

## Validation

A policy can parse cleanly and still be self-contradictory, e.g. a
`max_length` below `min_length`, or requiring more character classes than
`min_length` leaves room for. `validate` checks a parsed policy for these
and reports them without changing anything:

```
$ cat bad.rules
min_length=3
max_length=2
require_upper=true
require_lower=true
require_digit=true
require_symbol=true

$ cargo run -- validate bad.rules
max_length (2) is less than min_length (3); no password can satisfy both
4 character classes are required but min_length (3) is too short to fit one of each
```

This only inspects the rules format's field values against each other; it
doesn't check a candidate password.

## Library

The conversion logic lives in `src/policy.rs` and has no dependency on I/O:

```rust
use password_policy_convert::policy::{parse_rules, to_query};

let policy = parse_rules("min_length=12\nrequire_digit=true\n").unwrap();
let as_query = to_query(&policy);
```

Every public function takes its input, returns its output, and touches
nothing else — no file handles, no globals — so testing them is just
calling them with a string and checking the result. See the tests at the
bottom of `src/policy.rs`.

## Status

First pass. The field set covers length, character-class requirements, max
repeated characters, and minimum unique characters — enough for the two
policies I actually needed to migrate. It doesn't yet cover things like
forbidden substring lists or password history length.

It now reads (but does not write) PAM's `pwquality.conf` syntax. There's
still no scoring of an actual password against a policy — just the formats
and validation of a policy's own fields against each other.
