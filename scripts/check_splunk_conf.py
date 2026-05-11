#!/usr/bin/env python3
"""Minimal Splunk .conf syntax check. No Splunk install required.

A .conf file is INI-shaped with [stanza] headers and key=value
lines. Lines starting with # or ; are comments. Multi-line values
continue with a leading whitespace on the next line. We parse the
whole tree under the given path and fail on:

- a key=value line outside any stanza,
- a stanza header that does not match [name],
- a key with no `=` separator,
- a value continuation line at top-of-file before any stanza.

The check is intentionally permissive on the value side (any
string after `=` is fine) because Splunk does not constrain
search syntax inside savedsearches.conf at parse time; the spec
of `search` is enforced by the Splunk search head, not by the
config parser.
"""
from __future__ import annotations

import pathlib
import re
import sys

STANZA_RE = re.compile(r"^\[(?P<name>[^\]]+)\]\s*$")
KV_RE = re.compile(r"^(?P<key>[A-Za-z_][\w\-.]*)\s*=\s*(?P<value>.*)$")


def check_file(path: pathlib.Path) -> list[str]:
    errors: list[str] = []
    stanza: str | None = None
    with path.open(encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            if line.lstrip().startswith(("#", ";")):
                continue
            if line[0].isspace():
                # Value continuation. Allowed only when a stanza
                # and a prior key are in scope; we relax to "any
                # in-stanza whitespace-led line is a continuation."
                if stanza is None:
                    errors.append(
                        f"{path}:{lineno}: value-continuation before any stanza"
                    )
                continue
            m = STANZA_RE.match(line)
            if m:
                stanza = m.group("name")
                continue
            m = KV_RE.match(line)
            if m:
                if stanza is None:
                    errors.append(
                        f"{path}:{lineno}: key=value outside any stanza"
                    )
                continue
            errors.append(
                f"{path}:{lineno}: unrecognised line shape: {line!r}"
            )
    return errors


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_splunk_conf.py <dir>", file=sys.stderr)
        return 2
    root = pathlib.Path(argv[1])
    all_errors: list[str] = []
    for path in sorted(root.rglob("*.conf")):
        all_errors.extend(check_file(path))
    if all_errors:
        for e in all_errors:
            print(e, file=sys.stderr)
        return 1
    print(f"OK: parsed every .conf under {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
