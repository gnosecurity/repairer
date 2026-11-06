#!/usr/bin/env python3
"""A realm's answer must not depend on which realm asks.

    python3 scripts/check-realm-context.py [dir ...]

With no arguments it checks every realm in the repo (each gnomod.toml whose
module has an /r/ in its path).

THE RULE (gno-interrealm-v2.md §2 and its table in §2.1). Calling an exported
function of realm X without crossing (it has no `cur realm` first) runs X's
code on X's storage, but the realm ACTING stays the caller's: only a cross
changes it. chain/params keys every Get and Set by the realm acting, and
unsafe.CurrentRealm and unsafe.PreviousRealm walk the frames of whoever is
acting. So such a function that reaches one of them, itself or through the
package's own functions, answers for its caller and not for X. The Guards
realm's Level read params until 2026-11-06: another realm set its own
lvl_<hash>_<system> to "tested", and guards.Level handed it back for a guard
the realm never decided. Read what the realm keeps in its own storage instead.

ALSO CHECKED, both from gno-security-guide.md:
  - unsafe.OriginSend is read only after the same function checks that an
    account called directly: .IsUserCall() itself, or a call to a function of
    the package that does (§5.5). A MsgRun script passes IsUser, can spend
    the send, and then call in; so can a realm.
  - No other unsafe symbol: PreviousRealm and CurrentRealm walk the stack
    and OriginCaller is tx.origin; cur and cur.Previous() say who calls
    (§5.8).

The scan reads text, not an AST: a function reached only through a function
value is missed. The self-test below runs first, every time, so a pattern
that stops matching fails the check instead of passing it.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FUNC = re.compile(r"^func\s+(?:\((?P<recv>[^)]*)\)\s*)?(?P<name>\w+)\s*\((?P<params>[^)]*)\)", re.M)
CALL = re.compile(r"(?<![\w.])(\w+)\s*\(")
METHOD_CALL = re.compile(r"\.(\w+)\s*\(")
IMPORT = re.compile(r'^\s*(?:(\w+)\s+)?"([^"]+)"\s*$', re.M)


def strip(src):
    """src with comments, strings and runes blanked, newlines kept."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c in "\"'`":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\" and c != "`":
                    j += 1
                j += 1
            j = min(j + 1, n)
            out.append(c + re.sub(r"[^\n]", " ", src[i + 1 : j - 1]) + c)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def imports(src):
    """The local name of each import path, as the file names it."""
    names = {}
    block = re.search(r"^import\s*\((.*?)^\)", src, re.M | re.S)
    lines = block.group(1) if block else ""
    lines += "\n" + "\n".join(m.group(1) for m in re.finditer(r'^import\s+((?:\w+\s+)?"[^"]+")', src, re.M))
    for m in IMPORT.finditer(lines):
        names[m.group(2)] = m.group(1) or m.group(2).rsplit("/", 1)[-1]
    return names


def funcs(files):
    """{name: (file, line, crossing, exported, body)} for each top-level func
    and method; a method is keyed "Recv.Name". A func whose line ends in "{"
    ends at the next column-zero "}" (gofmt'd code); any other is the rest
    of its line."""
    out = {}
    for path, src in files:
        text = strip(src)
        for m in FUNC.finditer(text):
            eol = text.find("\n", m.end())
            eol = len(text) if eol < 0 else eol
            if text[:eol].rstrip().endswith("{"):
                end = text.find("\n}", eol)
                end = len(text) if end < 0 else end + 2
            else:
                end = eol
            body = text[m.end() : end]
            crossing = bool(re.fullmatch(r"\s*(?:\w+\s+)?realm\s*", m.group("params").split(",")[0]))
            name = m.group("name")
            key = name
            if m.group("recv"):
                key = m.group("recv").split()[-1].lstrip("*") + "." + name
            line = text.count("\n", 0, m.start()) + 1
            out[key] = (path, line, crossing, name[0].isupper(), body)
    return out


def check(files, label):
    """The findings for one package, given (path, source) pairs."""
    sources, unsafe_names = [], set()
    for _, src in files:
        im = imports(src)
        if "chain/params" in im:
            sources.append(re.escape(im["chain/params"]) + r"\.(?:Set|Get|UpdateParam)\w*\s*\(")
        if "chain/runtime/unsafe" in im:
            unsafe_names.add(im["chain/runtime/unsafe"])
    for u in unsafe_names:
        sources.append(re.escape(u) + r"\.(?:CurrentRealm|PreviousRealm)\s*\(")
    source = re.compile("|".join(sources)) if sources else None
    fs = funcs(files)
    by_name = {}
    for key in fs:
        by_name.setdefault(key.split(".")[-1], []).append(key)

    def callees(body):
        names = set(CALL.findall(body)) | set(METHOD_CALL.findall(body))
        return sorted(k for n in names for k in by_name.get(n, []))

    # reach[f]: the path from f to a realm-context read, if any.
    reach = {}
    for key, (_, _, _, _, body) in fs.items():
        if source:
            m = source.search(body)
            if m:
                reach[key] = [m.group(0).rstrip("( ").strip()]
    changed = True
    while changed:
        changed = False
        for key, (_, _, crossing, _, body) in fs.items():
            if key in reach or crossing:
                continue  # a crossing function acts as its own realm
            for c in callees(body):
                if c in reach and not fs[c][2]:
                    reach[key] = [c] + reach[c]
                    changed = True
                    break

    findings = []
    for key, (path, line, crossing, exported, _) in sorted(fs.items()):
        if exported and not crossing and key in reach:
            findings.append(f"{path}:{line}: {key} doesn't cross, so it runs as its caller, and it reaches "
                            f"{' -> '.join(reach[key])}: it answers for the caller's realm, not this one "
                            f"(gno-interrealm-v2.md §2); read the realm's own storage")

    checks_user = {k for k, v in fs.items() if ".IsUserCall()" in v[4]}
    for key, (path, line, _, _, body) in sorted(fs.items()):
        for u in sorted(unsafe_names):
            for m in re.finditer(re.escape(u) + r"\.(\w+)\s*\(", body):
                if m.group(1) != "OriginSend":
                    findings.append(f"{path}:{line}: {key} calls {u}.{m.group(1)}: use cur and cur.Previous() "
                                    f"(gno-security-guide.md §5.8)")
                    continue
                before = body[: m.start()]
                if ".IsUserCall()" in before or any(c in checks_user for c in callees(before)):
                    continue
                findings.append(f"{path}:{line}: {key} reads {u}.OriginSend without first checking "
                                f".IsUserCall(), itself or through this package: a MsgRun script or a realm "
                                f"can spend the send and then call (gno-security-guide.md §5.5)")
    census = f"{label}: {len(fs)} functions, {sum(1 for v in fs.values() if v[3] and not v[2])} exported " \
             f"that don't cross, {len(reach)} reaching params or the stack"
    return findings, census, len(fs)


SELFTEST = '''package v

import (
	"chain/params"
	"chain/runtime/unsafe"
)

var kept = map[string]string{}

func Get(k string) string { v, _ := params.GetString(k); return v } // BAD direct

func Via(k string) string { return helper(k) } // BAD through a helper

func helper(k string) string {
	v, _ := params.GetString("x_" + k)
	return v
}

func Kept(k string) string { return kept[k] } // good: storage

func Set(cur realm, k, v string) { params.SetString(k, v) } // good: crossing

func ViaSet(k string) string { return "params.GetString(k)" } // good: a string

func who() address { return unsafe.PreviousRealm().Address() }

func Who() address { return who() } // BAD through a helper

func caller(cur realm) address {
	if !cur.Previous().IsUserCall() {
		panic("no")
	}
	return cur.Previous().Address()
}

func Pay(cur realm) int64 { caller(cur); return unsafe.OriginSend().AmountOf("ugnot") } // good

func Free(cur realm) int64 { return unsafe.OriginSend().AmountOf("ugnot") } // BAD unchecked

func Late(cur realm) int64 { n := unsafe.OriginSend().AmountOf("ugnot"); caller(cur); return n } // BAD late

func Origin(cur realm) address { return unsafe.OriginCaller() } // BAD other unsafe
'''

# Each function the self-test must flag, and by which rule: unsafe.PreviousRealm
# in who (unexported) as another unsafe symbol, Who as an exported function
# reaching it.
SELFTEST_WANT = {
    ("Get", "doesn't cross"), ("Via", "doesn't cross"), ("Who", "doesn't cross"),
    ("who", "calls unsafe.PreviousRealm"), ("Origin", "calls unsafe.OriginCaller"),
    ("Free", "reads unsafe.OriginSend"), ("Late", "reads unsafe.OriginSend"),
}


def selftest():
    findings, _, _ = check([("selftest.gno", SELFTEST)], "selftest")
    got = set()
    for f in findings:
        rest = f.split(": ", 1)[1]
        name, _, said = rest.partition(" ")
        kind = next((k for n, k in SELFTEST_WANT if n == name and said.startswith(k)), said[:30])
        got.add((name, kind))
    if got != SELFTEST_WANT or len(findings) != len(SELFTEST_WANT):
        print("check-realm-context: the self-test failed, so the patterns no longer match what they must:")
        print("  want flagged:", sorted(SELFTEST_WANT))
        print("  got:", *findings, sep="\n    ")
        sys.exit(2)


def realms():
    for mod in sorted(ROOT.rglob("gnomod.toml")):
        if "vendor" in mod.parts:
            continue
        m = re.search(r'^module\s*=\s*"([^"]+)"', mod.read_text(), re.M)
        if m and "/r/" in m.group(1):
            yield mod.parent


def main():
    selftest()
    dirs = [pathlib.Path(a).resolve() for a in sys.argv[1:]] or list(realms())
    bad, total = [], 0
    for d in dirs:
        files = []
        for p in sorted(d.glob("*.gno")):
            if p.name.endswith(("_test.gno", "_filetest.gno")):
                continue
            try:
                rel = p.relative_to(ROOT)
            except ValueError:
                rel = p
            files.append((str(rel), p.read_text()))
        findings, census, n = check(files, str(d.relative_to(ROOT) if d.is_relative_to(ROOT) else d))
        total += n
        print(census)
        bad += findings
    if total == 0:
        print("check-realm-context: no functions found; nothing was checked")
        sys.exit(2)
    for f in bad:
        print(f)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
