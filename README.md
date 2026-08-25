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

There's also a JSON output format, for feeding a policy into something that
expects structured input:

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
```

If no file argument is given, input is read from stdin. Unknown keys,
missing values, and a missing `min_length`/`minLength` are reported as
errors rather than silently defaulted.

`to-json` is output-only for now — there's no parser for the JSON format,
since nothing downstream needs to write policies as JSON yet.

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
