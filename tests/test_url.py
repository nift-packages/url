#!/usr/bin/env python3
"""Initial certification suite for the zero-dependency RFC 3986 url package."""

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


NIFT = Path(sys.argv[1] if len(sys.argv) > 1 else "nift").resolve()
PACKAGE = Path(__file__).resolve().parent.parent
TESTS = PACKAGE / "tests"


def run(path, cwd, no_process=False, timeout=60):
    command = [str(NIFT), path]
    if no_process:
        command.append("--no-process")
    return subprocess.run(command, cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=timeout, check=False)


def require(condition, message, result=None):
    if condition:
        return
    detail = ""
    if result is not None:
        detail = f"\nrc={result.returncode}\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    raise AssertionError(message + detail)


manifest = json.loads((PACKAGE / "manifest.json").read_text(encoding="ascii"))
require(manifest == {
    "name": "url",
    "version": "0.1.0",
    "entry": "src/url.f",
    "description": "Deterministic RFC 3986 URI-reference parsing and resolution",
}, "manifest contract differs")
require("dependencies" not in manifest and "resources" not in manifest,
        "manifest must have zero dependencies/resources")

source = (PACKAGE / "src" / "url.f").read_text(encoding="ascii")
public = re.findall(r"^    fn\(([A-Za-z_][A-Za-z0-9_]*)\(", source, re.MULTILINE)
private = re.findall(r"^    private fn\(([A-Za-z_][A-Za-z0-9_]*)\(", source, re.MULTILINE)
exports = re.findall(r"^export\(([^)]+)\)$", source, re.MULTILINE)
require(public == ["parse", "stringify", "resolve", "resolve_string", "percent_encode",
                   "percent_decode", "encode", "decode", "parse_query", "build_query"],
        f"exact facade differs: {public!r}")
require(exports == ["url"], f"url must be the sole export: {exports!r}")
require(private and all(name not in public for name in private), "helpers must be private")

normal = {
    "g:h": "g:h", "g": "http://a/b/c/g", "./g": "http://a/b/c/g",
    "g/": "http://a/b/c/g/", "/g": "http://a/g", "//g": "http://g",
    "?y": "http://a/b/c/d;p?y", "g?y": "http://a/b/c/g?y",
    "#s": "http://a/b/c/d;p?q#s", "g#s": "http://a/b/c/g#s",
    "g?y#s": "http://a/b/c/g?y#s", ";x": "http://a/b/c/;x",
    "g;x": "http://a/b/c/g;x", "g;x?y#s": "http://a/b/c/g;x?y#s",
    "": "http://a/b/c/d;p?q", ".": "http://a/b/c/", "./": "http://a/b/c/",
    "..": "http://a/b/", "../": "http://a/b/", "../g": "http://a/b/g",
    "../..": "http://a/", "../../": "http://a/", "../../g": "http://a/g",
}
abnormal = {
    "../../../g": "http://a/g", "../../../../g": "http://a/g",
    "/./g": "http://a/g", "/../g": "http://a/g", "g.": "http://a/b/c/g.",
    ".g": "http://a/b/c/.g", "g..": "http://a/b/c/g..", "..g": "http://a/b/c/..g",
    "./../g": "http://a/b/g", "./g/.": "http://a/b/c/g/",
    "g/./h": "http://a/b/c/g/h", "g/../h": "http://a/b/c/h",
    "g;x=1/./y": "http://a/b/c/g;x=1/y", "g;x=1/../y": "http://a/b/c/y",
    "g?y/./x": "http://a/b/c/g?y/./x", "g?y/../x": "http://a/b/c/g?y/../x",
    "g#s/./x": "http://a/b/c/g#s/./x", "g#s/../x": "http://a/b/c/g#s/../x",
    "http:g": "http:g",
}

matrix_lines = []
for reference, expected in [*normal.items(), *abnormal.items()]:
    matrix_lines.append(
        f'expect(url.resolve_string("http://a/b/c/d;p?q", {json.dumps(reference)}) == '
        f'{json.dumps(expected)}, {json.dumps("matrix " + reference)})'
    )

invalid_utf8 = []
invalid_utf8.extend(f"%{value:02X}" for value in range(0x80, 0xC2))
invalid_utf8.extend(f"%{value:02X}" for value in range(0xF5, 0x100))
invalid_utf8.extend([
    "%C2", "%C2%20", "%DF", "%DF%7F",
    "%E0", "%E0%A0", "%E0%80%80", "%E0%9F%BF", "%E0%A0%20",
    "%E1", "%E1%80", "%E1%20%80", "%E1%80%20", "%ED%A0%80",
    "%EF", "%EF%BF", "%EF%20%80", "%EF%BF%20",
    "%F0", "%F0%90", "%F0%90%80", "%F0%80%80%80", "%F0%8F%BF%BF",
    "%F0%90%20%80", "%F0%90%80%20", "%F4%90%80%80",
    "%F1", "%F1%80", "%F1%80%80", "%F1%20%80%80", "%F1%80%20%80",
])
utf8_lines = []
for index, encoded in enumerate(invalid_utf8):
    utf8_lines.append(f'expect(url.decode("{encoded}") == null, "invalid UTF-8 decode {index}")')
    utf8_lines.append(f'expect(url.parse_query("{encoded}=x") == null, "invalid UTF-8 query name {index}")')
    utf8_lines.append(f'expect(url.parse_query("x={encoded}") == null, "invalid UTF-8 query value {index}")')

valid_shape = {
    "valid": True, "error": None, "error_code": None, "scheme": "http",
    "has_authority": True, "userinfo": None, "host": "example.com", "port": None,
    "host_is_ip_literal": False, "path": "/", "has_query": False, "query": None,
    "has_fragment": False, "fragment": None,
}
forged_values = [
    {}, {"valid": True},
    {**valid_shape, "valid": "true"},
    {**valid_shape, "error": "forged"},
    {**valid_shape, "scheme": 7},
    {**valid_shape, "scheme": "1bad"},
    {**valid_shape, "has_authority": False},
    {**valid_shape, "host": 7},
    {**valid_shape, "userinfo": 7},
    {**valid_shape, "port": "bad"},
    {**valid_shape, "host_is_ip_literal": True, "host": "not-ip"},
    {**valid_shape, "path": "%GG"},
    {**valid_shape, "scheme": "x", "has_authority": False, "userinfo": None,
     "host": None, "port": None, "host_is_ip_literal": False, "path": "//b"},
    {**valid_shape, "has_query": True, "query": None},
    {**valid_shape, "has_query": False, "query": "x"},
    {**valid_shape, "has_fragment": True, "fragment": None},
    {**valid_shape, "has_fragment": False, "fragment": "x"},
]
forged_lines = []
for index, value in enumerate(forged_values):
    literal = json.dumps(value, separators=(",", ":"))
    forged_lines.append(f'expect(url.stringify({literal}) == null, "forged stringify {index}")')
    forged_lines.append(f'expect(url.resolve({literal}, "g").error_code == "invalid_base", "forged resolve {index}")')

adversarial_reference = "x:" + ("a/" * 1300) + ("../" * 1300) + "z"

contract = r'''
fn(expect(condition, label)) { if(!condition) { print("FAIL " + label); missing.value } }
p := url.parse("https://user:pw@[2001:db8::1]:8080/a/b?x=#")
expect(type(p) == "object" && p.valid, "ordinary valid parse result")
expect(p.scheme == "https" && p.has_authority && p.userinfo == "user:pw", "scheme authority userinfo")
expect(p.host == "2001:db8::1" && p.host_is_ip_literal && p.port == "8080", "IP literal and port")
expect(p.path == "/a/b" && p.has_query && p.query == "x=" && p.has_fragment && p.fragment == "", "component presence")
expect(url.stringify(p) == "https://user:pw@[2001:db8::1]:8080/a/b?x=#", "parse/stringify")
expect(url.parse("").valid && url.parse("").path == "", "empty relative reference")
expect(url.parse("?").has_query && url.parse("?").query == "", "empty query present")
expect(!url.parse("").has_query && url.parse("").query == null, "query absent")
expect(url.parse("#").has_fragment && url.parse("#").fragment == "", "empty fragment present")
expect(url.parse("//").has_authority && url.parse("//").host == "", "empty authority")
expect(url.parse("mailto:John.Doe@example.com").valid, "mailto URI")
expect(url.parse("urn:example:animal:ferret:nose").valid, "URN")
expect(url.parse("//[v1.fe80]:").valid && url.parse("//[v1.fe80]:").port == "", "IPvFuture and empty port")
expect(url.parse("a/b:c").valid && url.parse("a/b:c").scheme == null, "colon after first relative segment")
expect(url.resolve_string("http://a/b/c/d", "%2e%2e/g") == "http://a/b/c/%2e%2e/g", "encoded dots remain data")
expect(url.resolve_string("x:a/../b", "") == "x:a/../b", "empty reference preserves rootless base")
expect(url.resolve_string("z:q", "x:a/../b") == "x:/b", "rootless scheme dot removal")
expect(url.resolve_string("x:a/b", "../c") == "x:/c", "rootless base merge dot removal")
expect(url.resolve_string("z:q", "x:a/b/../../c") == "x:/c", "rootless repeated parent removal")
expect(url.resolve_string("z:q", "x:a/..//b") == "x://b", "scheme path recomposes as authority")
scheme_authority := url.resolve(url.parse("z:q"), "x:a/..//b")
expect(scheme_authority.valid && scheme_authority.error_code == null && scheme_authority.has_authority && scheme_authority.host == "b" && scheme_authority.path == "", "scheme path canonical result shape")
expect(url.resolve_string("x:q", "a/..//b") == "x://b", "inherited scheme path recomposes as authority")
expect(url.resolve_string("x:a/b", "../..//b") == "x://b", "inherited rootless base recomposition")
expect(url.resolve_string("http://a/c", "../..//b") == "http://a//b", "inherited authority keeps repeated slash path")
expect(url.resolve_string("z:q", "x:a//../b") == "x:a/b", "rootless repeated slash parent")
expect(url.resolve_string("z:q", "x:/a//b/../c") == "x:/a//c", "absolute repeated slash parent")
expect(url.resolve_string("z:q", "x:a/b/.") == "x:a/b/", "terminal dot")
expect(url.resolve_string("z:q", "x:a/b/..") == "x:a/", "terminal parent")
expect(url.resolve_string("z:q", "x:/a/../../b") == "x:/b", "absolute parents above root")

encoded := url.percent_encode(bytes([0, 32, 43, 47, 65, 126, 255]))
expect(encoded == "%00%20%2B%2FA~%FF", "octet percent encoding")
expect(url.percent_decode(encoded) == bytes([0, 32, 43, 47, 65, 126, 255]), "octet percent decoding")
expect(url.encode("caf" + bytes([195, 169]).decode("utf-8")) == "caf%C3%A9", "UTF-8 encode")
expect(url.decode("caf%C3%A9") == "caf" + bytes([195, 169]).decode("utf-8"), "UTF-8 decode")
expect(url.decode("a+b") == "a+b" && url.encode("a+b") == "a%2Bb", "no form plus behavior")
expect(url.decode("%C2%80") != null && url.decode("%E0%A0%80") != null, "valid UTF-8 lower boundaries")
expect(url.decode("%ED%9F%BF") != null && url.decode("%F0%90%80%80") != null && url.decode("%F4%8F%BF%BF") != null, "valid UTF-8 upper boundaries")

pairs := url.parse_query("a=1&a=2&flag&empty=&plus=a+b")
expect(type(pairs) == "array" && pairs.length() == 5, "ordered query array")
expect(pairs[0].name == "a" && pairs[0].value == "1" && pairs[1].name == "a" && pairs[1].value == "2", "duplicates retained")
expect(!pairs[2].has_value && pairs[2].value == null, "query flag")
expect(pairs[3].has_value && pairs[3].value == "", "query empty value")
expect(pairs[4].value == "a+b", "query plus literal")
expect(url.build_query(pairs) == "a=1&a=2&flag&empty=&plus=a%2Bb", "query rebuild")
expect(url.parse_query("").length() == 0 && url.build_query([]) == "", "empty query pairs")
expect(url.build_query([{"name":"","has_value":false,"value":null}]) == "", "empty singleton query ambiguity")
expect(url.build_query([{"name":"x","has_value":false}]) == null, "query pair requires complete shape")
''' + "\n".join(matrix_lines + utf8_lines + forged_lines) + r'''
baseline := url.resolve_string("http://a/b/c/d;p?q", "../g?x=#f")
i := 0
while(i < 20) { expect(url.resolve_string("http://a/b/c/d;p?q", "../g?x=#f") == baseline, "determinism"); i += 1 }
print("PASS url contract")
'''

boundary_contract = r'''@import("url")
fn(expect(condition, label)) { if(!condition) { print("FAIL " + label); missing.value } }
limit_text := "a"
limit_size := 1
while(limit_size < 8192) { limit_text += limit_text; limit_size *= 2 }
above_limit := limit_text + "a"
expect(limit_text.length() == 8192 && above_limit.length() == 8193, "exact boundary fixture sizes")
parsed_limit := url.parse(limit_text)
parsed_above := url.parse(above_limit)
expect(parsed_limit.valid && parsed_limit.path.length() == 8192, "URI exact input limit")
expect(!parsed_above.valid && parsed_above.error_code == "input_too_large", "URI above input limit")
expect(url.encode(limit_text) == limit_text && url.percent_encode(limit_text.encode("utf-8")) == limit_text, "encode exact input limit")
expect(url.encode(above_limit) == null && url.percent_encode(above_limit.encode("utf-8")) == null, "encode above input limit")
expect(url.decode(limit_text) == limit_text && url.percent_decode(limit_text) == limit_text.encode("utf-8"), "decode exact input limit")
expect(url.decode(above_limit) == null && url.percent_decode(above_limit) == null, "decode above input limit")
limit_pairs := url.parse_query(limit_text)
expect(limit_pairs != null && limit_pairs.length() == 1 && limit_pairs[0].name.length() == 8192, "parse_query exact input limit")
expect(url.parse_query(above_limit) == null, "parse_query above input limit")
expect(url.build_query([{"name":limit_text,"has_value":false,"value":null}]) == limit_text, "build_query exact input limit")
expect(url.build_query([{"name":above_limit,"has_value":false,"value":null}]) == null, "build_query above input limit")
limit_uri := "x:" + limit_text.substr(0, 8190)
expect(url.resolve_string("z:q", limit_uri) == limit_uri, "resolve exact reference limit")
large_base := "x:/" + limit_text.substr(0, 8187) + "/"
oversized_resolution := url.resolve(url.parse(large_base), "ab")
expect(!oversized_resolution.valid && oversized_resolution.error_code == "output_too_large", "resolved output limit")
expect(url.resolve(url.parse("x:q"), above_limit).error_code == "input_too_large", "resolve above reference limit")
expect(url.resolve_string(above_limit, "g") == null && url.resolve_string("x:q", above_limit) == null, "resolve_string inputs independently bounded")
oversized_value := {"valid":true,"error":null,"error_code":null,"scheme":null,"has_authority":false,"userinfo":null,"host":null,"port":null,"host_is_ip_literal":false,"path":above_limit,"has_query":false,"query":null,"has_fragment":false,"fragment":null}
expect(url.stringify(oversized_value) == null, "stringify above output limit")
expect(url.resolve(oversized_value, "g").error_code == "invalid_base", "resolve forged oversized base")
print("PASS url boundaries")
'''

performance_contract = f'''@import("url")
fn(expect(condition, label)) {{ if(!condition) {{ print("FAIL " + label); missing.value }} }}
reference := {json.dumps(adversarial_reference)}
expect(reference.length() == 6503, "adversarial fixture size")
expect(url.resolve_string("z:q", reference) == "x:/z", "grow then unwind")
print("PASS url dot-segment performance")
'''

malformed = [
    'url.parse("1bad:thing").valid', 'url.parse("//a@b@c/").valid',
    'url.parse("//[2001:db8::1/").valid', 'url.parse("//2001:db8::1/").valid',
    'url.parse("//[not-ip]/").valid', 'url.parse("//[::1]tail/").valid',
    'url.parse("//host:abc/").valid', 'url.parse("//host:8x/").valid',
    'url.parse("/%").valid', 'url.parse("/%0").valid', 'url.parse("/%GG").valid',
    'url.parse("/?bad=%XZ").valid', 'url.parse("/#bad=%XZ").valid',
]

work_context = tempfile.TemporaryDirectory(prefix=".url-test-", dir=TESTS)
work = Path(work_context.name)
try:
    suite_started = time.perf_counter()
    direct = work / "direct"
    consumer = work / "consumer"
    direct.mkdir()
    (consumer / ".nift").mkdir(parents=True)
    (direct / "contract.f").write_text('@import("../../../src/url.f")\n' + contract,
                                       encoding="ascii")
    result = run("contract.f", direct)
    require(result.returncode == 0 and result.stdout.strip() == "PASS url contract",
            "direct source contract failed", result)

    added = subprocess.run([str(NIFT), "add", str(PACKAGE)], cwd=consumer,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=30, check=False)
    require(added.returncode == 0, "fresh nift add failed", added)
    (consumer / "contract.f").write_text('@import("url")\n' + contract, encoding="ascii")
    installed = run("contract.f", consumer)
    require(installed.returncode == 0 and installed.stdout.strip() == "PASS url contract",
            "installed contract failed", installed)
    restricted = run("contract.f", consumer, no_process=True)
    require(restricted.returncode == 0 and restricted.stdout == installed.stdout,
            "--no-process contract failed", restricted)
    (consumer / "boundaries.f").write_text(boundary_contract, encoding="ascii")
    boundary_started = time.perf_counter()
    boundaries = run("boundaries.f", consumer, no_process=True, timeout=30)
    boundary_seconds = time.perf_counter() - boundary_started
    require(boundaries.returncode == 0 and boundaries.stdout.strip() == "PASS url boundaries",
            "boundary contract failed", boundaries)
    require(boundary_seconds < 30, f"boundary contract exceeded 30 seconds: {boundary_seconds:.3f}s")
    (consumer / "performance.f").write_text(performance_contract, encoding="ascii")
    performance_started = time.perf_counter()
    performance = run("performance.f", consumer, no_process=True, timeout=10)
    performance_seconds = time.perf_counter() - performance_started
    require(performance.returncode == 0 and performance.stdout.strip() == "PASS url dot-segment performance",
            "dot-segment performance contract failed", performance)
    require(performance_seconds < 10,
            f"dot-segment performance contract exceeded 10 seconds: {performance_seconds:.3f}s")
    repeated = run("contract.f", consumer)
    require((repeated.returncode, repeated.stdout, repeated.stderr) ==
            (installed.returncode, installed.stdout, installed.stderr),
            "repeated run was not deterministic", repeated)

    for index, expression in enumerate(malformed):
        path = consumer / f"malformed-{index}.f"
        path.write_text(f'@import("url")\nif({expression}) {{ missing.rejected }}\nprint("PASS")\n',
                        encoding="ascii")
        rejected = run(path.name, consumer)
        require(rejected.returncode == 0 and rejected.stdout.strip() == "PASS",
                f"malformed URI accepted: {expression}", rejected)
    for value in ["%", "%0", "%GG", "a%4Z"]:
        path = consumer / "bad-percent.f"
        path.write_text(f'@import("url")\nif(url.percent_decode("{value}") != null) {{ missing.rejected }}\nprint("PASS")\n', encoding="ascii")
        rejected = run(path.name, consumer)
        require(rejected.returncode == 0, f"malformed percent triplet accepted: {value}", rejected)

    for helper in private:
        path = consumer / "private.f"
        path.write_text(f'@import("url")\nurl.{helper}()\n', encoding="ascii")
        hidden = run(path.name, consumer)
        require(hidden.returncode != 0 and f"private struct method: {helper}" in hidden.stderr,
                f"private helper exposed: {helper}", hidden)
    global_check = consumer / "global.f"
    global_check.write_text('@import("url")\nprint(remove_dot_segments)\n', encoding="ascii")
    require(run(global_check.name, consumer).returncode != 0, "private global leaked")

    suite_seconds = time.perf_counter() - suite_started
    require(suite_seconds < 180, f"full suite exceeded 180 seconds: {suite_seconds:.3f}s")

    print("PASS direct source import")
    print("PASS fresh nift add and sole facade export")
    print("PASS RFC 3986 section 5.4 normal and abnormal matrix")
    print("PASS malformed UTF-8, forged object, boundary, deterministic, and --no-process checks")
    print(f"TIMING boundary={boundary_seconds:.3f}s adversarial={performance_seconds:.3f}s full={suite_seconds:.3f}s")
finally:
    work_context.cleanup()
