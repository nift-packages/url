# url

Dependency-free RFC 3986 URI-reference parsing, serialization, reference
resolution, percent coding, and ordered query-pair utilities for Nift. This is
not a WHATWG URL parser: it performs no browser normalization, form encoding,
IDNA conversion, or IRI processing.

```f
@import("url")

parsed := url.parse("https://user@example.com:8443/a?x=#part")
print(parsed.valid)
print(url.resolve_string("http://a/b/c/d;p?q", "../g"))
```

## Parse Values

`url.parse(text)` always returns an ordinary object. A valid result contains:

- `valid: true`, with `error` and `error_code` set to `null`
- `scheme`, `userinfo`, `host`, and `port`, each a string or `null`
- `has_authority` and `host_is_ip_literal` booleans
- `path`, always a string
- `has_query`/`query` and `has_fragment`/`fragment`

Presence booleans distinguish absent components from empty ones. For example,
`url.parse("?")` has `has_query == true` and `query == ""`. Invalid input
returns the same stable shape with `valid: false` and string diagnostics.
Raw non-ASCII input is rejected; non-ASCII data must be UTF-8 percent encoded.
Multiple raw `@` delimiters in an authority are rejected rather than treating
the last one specially. Empty ports are permitted by RFC 3986's `port` grammar.
Because `userinfo` can contain credentials, applications should redact it when
logging or displaying parsed URI values.

`url.stringify(value)` serializes a valid parse-shaped ordinary object and
returns `null` for an invalid, incomplete, inconsistent, or non-canonical
object. It validates every required member and reparses the serialization before
returning it. Component spelling and case are preserved.

## Resolution

- `url.resolve(base, reference)` accepts a valid parsed base object and a
  reference string, returning a parsed result object.
- `url.resolve_string(base, reference)` accepts two strings and returns the
  resolved string, or `null` when either input cannot be used.

Resolution follows RFC 3986 section 5.2. Percent-encoded dots such as `%2e`
are data and are never treated as dot segments. This includes section 5.2.4's
rootless-path behavior; for example, resolving `x:a/../b` as an absolute
reference produces `x:/b`. Recomposition is reparsed into the canonical result
shape, so `x:a/..//b` produces `x://b` with authority `b`. This does not relax
`stringify`: forged non-canonical component objects are still rejected.

## Percent Coding

- `url.percent_encode(value)` accepts `bytes` and leaves only RFC 3986
  unreserved octets literal.
- `url.percent_decode(text)` returns `bytes`, or `null` for a malformed triplet.
- `url.encode(text)` percent-encodes the text's UTF-8 bytes.
- `url.decode(text)` strictly validates the decoded bytes as UTF-8 before
  decoding and returns `null` for overlong encodings, surrogates, out-of-range
  code points, truncation, or malformed continuation bytes.

These functions do not implement HTML form behavior: `+` encodes as `%2B` and
decodes as a literal plus unless represented by `%2B`.

## Query Pairs

`url.parse_query(query)` returns an ordered array of ordinary objects with
`name`, `has_value`, and `value`. Duplicate names and ordering are retained;
`flag` has `has_value == false`, while `empty=` has `has_value == true` and an
empty value. `url.build_query(parameters)` performs the inverse operation.
Neither operation maps `+` to space. Decoded names and values must be strict
UTF-8 or `parse_query` returns `null`.

The empty query string is inherently ambiguous in this pair representation.
`parse_query("")` returns `[]`, while both `build_query([])` and a singleton
empty flag (`[{"name":"","has_value":false,"value":null}]`) produce `""`.
Consequently that singleton does not round-trip through `parse_query`.

## Limits

All limits are deterministic and measured in bytes:

- URI references accepted by `parse`, base serializations used by `stringify`
  and `resolve`, and reference strings are limited to 8,192 UTF-8 bytes.
- `encode` input text, `decode`/`percent_decode` input text, and
  `percent_encode` input bytes are limited to 8,192 bytes. Percent encoding can
  produce at most 24,576 ASCII bytes.
- `parse_query` input is limited to 8,192 UTF-8 bytes. `build_query` permits at
  most 8,192 UTF-8 bytes across names, values, `&` separators, and `=` markers
  before percent encoding.

`parse` reports `input_too_large` in its invalid result. `resolve` propagates
that result for an oversized reference, reports `invalid_base` for malformed or
forged bases, and reports `output_too_large` if merging would exceed the URI
limit. `stringify`, `resolve_string`, percent/text APIs, and query APIs return
`null` for their corresponding size failures.

## Testing

```sh
python3 tests/test_url.py /path/to/nift
```

The suite checks direct source import, a fresh local package install, the exact
sole export and private helpers, malformed syntax, unusual valid references,
strict UTF-8 classes, adversarial parse-shaped objects, the complete RFC 3986
section 5.4 normal and abnormal resolution matrix, rootless dot-segment cases,
repeated-slash and terminal-dot cases, a timing-bounded grow-then-unwind path,
exact and over-limit inputs, deterministic repetition, `--no-process`, and
temporary-file cleanup.
