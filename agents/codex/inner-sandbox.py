#!/usr/bin/env python3
"""inner-sandbox.py MODE — adjust Codex's own sandbox in a config.toml.

Reads a config.toml on stdin and writes the edited file to stdout. Used by
agents/codex/overlay.sh on the sandbox-private copy of the user's config
(never on the real ~/.codex/config.toml).

Codex starts a sandbox of its own (bubblewrap) for every command it runs.
Inside agent-sandbox that cannot work: the seccomp filter denies mount(2)
and friends, and firejail blocks user namespaces. Every command then fails
with "bwrap: Failed to make / slave: Operation not permitted". Modes:

  off        sandbox_mode = "danger-full-access" (top level, and in every
             [profiles.NAME] table that sets its own sandbox_mode, which
             would win over the top-level key). Codex then runs commands
             without a sandbox of its own; agent-sandbox still confines
             them. The only option when Codex has no usable fallback.
  landlock   [features] use_legacy_landlock = true. Codex then uses its
             Landlock sandbox, which needs no mount(2) and works inside
             agent-sandbox. Keeps Codex's own restrictions. Needs a kernel
             with Landlock (5.13+).
  keep       no edit; only undoes an earlier one.

The private copy outlives a launch (it is kept while it is newer than the
real file, so Codex's own changes to it survive), and the same copy is
used by launches on other backends and hosts. Every edit therefore
carries a marker and every run first UNDOES the markers of earlier runs,
then applies its own mode. A launch never inherits a choice made by an
earlier one, `keep` restores the file, and running a mode twice is a
no-op:

  - a key that was added:    "# agent-sandbox: <why> (added)" above it
  - a [features] table that was added (three lines): "... (added table)"
  - a value that was replaced: the original text after "=" is kept at the
    end of the line after "# agent-sandbox-orig: ".

Exit status: 0 = the edited (or already correct) file is on stdout;
3 = the file is on stdout UNCHANGED and the reason is on stderr (a shape
this editor will not touch, e.g. a multi-line sandbox_mode value, or a
file that is not valid TOML when the check is available).

The editor is line based so it runs on any Python >= 3.6 (no tomllib, no
third-party packages): a small scanner tracks strings, comments and
bracket depth so that only lines at the top level of the document are
treated as table headers or keys. When tomllib exists (Python 3.11+) the
result is parsed and checked before it is returned.
"""

import re
import sys

KEY_PART = r'(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|\'[^\']*\')'
DOTTED = KEY_PART + r'(?:\s*\.\s*' + KEY_PART + r')*'
KEY_RE = re.compile(r'^(\s*)(' + DOTTED + r')(\s*=\s*)')
HDR_RE = re.compile(r'^\s*(\[\[?)\s*(' + DOTTED + r')\s*(\]\]?)\s*(?:#.*)?$')
STR_VALUE_RE = re.compile(r'^("(?:[^"\\]|\\.)*"|\'[^\']*\')(\s*(?:#.*)?)$')
BOOL_VALUE_RE = re.compile(r'^(true|false)(\s*(?:#.*)?)$')

ADDED_RE = re.compile(r'^\s*# agent-sandbox: .* \(added(, no final newline)?\)\s*$')
ADDED_TABLE_RE = re.compile(r'^\s*# agent-sandbox: .* \(added table(, no final newline)?\)\s*$')
ORIG_MARK = " # agent-sandbox-orig:"


class Refuse(Exception):
    pass


def key_parts(dotted):
    parts = []
    for p in re.findall(KEY_PART, dotted):
        if p[0] in "\"'":
            p = p[1:-1]
        parts.append(p)
    return tuple(parts)


def line_states(lines):
    """(bracket depth, inside a multi-line string) at the start of each line."""
    states = []
    mode = None  # None | 'ml_basic' | 'ml_lit'
    depth = 0
    for line in lines:
        states.append((depth, mode))
        i, n = 0, len(line)
        while i < n:
            c = line[i]
            if mode == "ml_basic":
                if c == "\\":
                    i += 2
                elif line.startswith('"""', i):
                    mode = None
                    i += 3
                else:
                    i += 1
                continue
            if mode == "ml_lit":
                if line.startswith("'''", i):
                    mode = None
                    i += 3
                else:
                    i += 1
                continue
            if c == "#":
                break
            if line.startswith('"""', i):
                mode = "ml_basic"
                i += 3
                continue
            if line.startswith("'''", i):
                mode = "ml_lit"
                i += 3
                continue
            if c == '"':
                i += 1
                while i < n and line[i] != '"':
                    i += 2 if line[i] == "\\" else 1
                i += 1
                continue
            if c == "'":
                j = line.find("'", i + 1)
                i = n if j < 0 else j + 1
                continue
            if c in "[{":
                depth += 1
            elif c in "]}":
                depth = max(0, depth - 1)
            i += 1
    states.append((depth, mode))
    return states


def at_top(states, idx):
    return states[idx] == (0, None)


def headers(lines, states):
    """[(line index, '[' or '[[', parts)] for every table header."""
    out = []
    for idx, line in enumerate(lines):
        if not at_top(states, idx):
            continue
        m = HDR_RE.match(line.rstrip("\r"))
        if m:
            out.append((idx, m.group(1), key_parts(m.group(2))))
    return out


def eol_of(line):
    return "\r" if line.endswith("\r") else ""


def single_line_value(states, idx, nlines):
    """True when the value starting on line idx ends on that line."""
    return idx + 1 >= nlines or at_top(states, idx + 1)


def replace_value(lines, states, idx, key_match, regex, new_value):
    """Set the value on line idx to new_value, remembering the original
    text after "=" at the end of the line (see restore). A value that is
    already new_value is left alone."""
    if not single_line_value(states, idx, len(lines)):
        raise Refuse("the value on line %d spans several lines" % (idx + 1))
    line = lines[idx]
    rest = line[key_match.end():].rstrip("\r")
    m = regex.match(rest)
    if m and m.group(1) == new_value:
        return
    lines[idx] = (line[:key_match.end()] + new_value + ORIG_MARK + " " + rest
                  + eol_of(line))


def restore(lines):
    """Undo the edits of earlier runs (see the module docstring)."""
    states = line_states(lines)
    drop = set()
    rewrite = {}
    strip_final_newline = False
    n = len(lines)
    for idx, line in enumerate(lines):
        if not at_top(states, idx):
            continue
        bare = line.rstrip("\r")
        if ADDED_RE.match(bare) and idx + 1 < n and at_top(states, idx + 1) \
                and not HDR_RE.match(lines[idx + 1].rstrip("\r")):
            drop.update((idx, idx + 1))
            if ADDED_RE.match(bare).group(1):
                strip_final_newline = True
        elif ADDED_TABLE_RE.match(bare) and idx + 2 < n \
                and lines[idx + 1].rstrip("\r").strip() == "[features]" \
                and at_top(states, idx + 2):
            km = KEY_RE.match(lines[idx + 2])
            if km and key_parts(km.group(2)) == ("use_legacy_landlock",):
                drop.update((idx, idx + 1, idx + 2))
                if ADDED_TABLE_RE.match(bare).group(1):
                    strip_final_newline = True
        else:
            km = KEY_RE.match(line)
            if km:
                rest = line[km.end():].rstrip("\r")
                pos = rest.find(ORIG_MARK)
                if pos >= 0:
                    orig = rest[pos + len(ORIG_MARK):]
                    if orig.startswith(" "):
                        orig = orig[1:]
                    rewrite[idx] = line[:km.end()] + orig + eol_of(line)
    out = [rewrite.get(i, l) for i, l in enumerate(lines) if i not in drop]
    if strip_final_newline and out and out[-1] == "":
        out.pop()       # the file had no final newline before the block
    return out


def edit_off(lines):
    """sandbox_mode = "danger-full-access" at top level and in profiles."""
    states = line_states(lines)
    table = ()
    found_top = False
    first_header = None
    for idx, line in enumerate(lines):
        if not at_top(states, idx):
            continue
        hm = HDR_RE.match(line.rstrip("\r"))
        if hm:
            if first_header is None:
                first_header = idx
            parts = key_parts(hm.group(2))
            table = parts if hm.group(1) == "[" else ("[[",) + parts
            continue
        km = KEY_RE.match(line)
        if not km:
            continue
        full = table + key_parts(km.group(2))
        if full == ("sandbox_mode",) or (
                len(full) == 3 and full[0] == "profiles" and full[2] == "sandbox_mode"):
            replace_value(lines, states, idx, km, STR_VALUE_RE, '"danger-full-access"')
            if full == ("sandbox_mode",):
                found_top = True
    if not found_top:
        eol = "\r" if any(l.endswith("\r") for l in lines) else ""
        nonl = first_header is None and bool(lines) and lines[-1] not in ("", "\r")
        block = ["# agent-sandbox: Codex's own sandbox cannot start inside "
                 "agent-sandbox (added%s)" % (", no final newline" if nonl else "") + eol,
                 'sandbox_mode = "danger-full-access"' + eol]
        if first_header is not None:
            lines[first_header:first_header] = block
        else:
            _append(lines, block, eol, blank_before=False)
    return lines


def _append(lines, block, eol, blank_before):
    """Append block at the end of the file, keeping a final newline."""
    if lines and lines[-1] == "":
        lines.pop()
    elif lines and lines[-1] == "\r":
        lines.pop()
    if blank_before and lines:
        lines.append(eol)
    lines.extend(block)
    lines.append("")


def edit_landlock(lines):
    """[features] use_legacy_landlock = true."""
    states = line_states(lines)
    hdrs = headers(lines, states)
    feat = [h for h in hdrs if h[1] == "[" and h[2] == ("features",)]
    if feat:
        hidx = feat[0][0]
        nxt = len(lines)
        for h in hdrs:
            if h[0] > hidx:
                nxt = h[0]
                break
        for idx in range(hidx + 1, nxt):
            if not at_top(states, idx):
                continue
            km = KEY_RE.match(lines[idx])
            if km and key_parts(km.group(2)) == ("use_legacy_landlock",):
                replace_value(lines, states, idx, km, BOOL_VALUE_RE, "true")
                return lines
        eol = eol_of(lines[hidx])
        lines[hidx + 1:hidx + 1] = [
            "# agent-sandbox: Codex's own bubblewrap sandbox cannot start "
            "inside agent-sandbox; its Landlock sandbox can (added)" + eol,
            "use_legacy_landlock = true" + eol]
        return lines
    first_header = hdrs[0][0] if hdrs else len(lines)
    for idx in range(first_header):
        if not at_top(states, idx):
            continue
        km = KEY_RE.match(lines[idx])
        if km and key_parts(km.group(2))[:1] == ("features",):
            raise Refuse("'features' is defined at the top level of the file "
                         "(line %d), not as a [features] table" % (idx + 1))
    eol = "\r" if any(l.endswith("\r") for l in lines) else ""
    nonl = bool(lines) and lines[-1] not in ("", "\r")
    _append(lines, ["# agent-sandbox: Codex's own bubblewrap sandbox cannot start "
                    "inside agent-sandbox; its Landlock sandbox can (added table%s)"
                    % (", no final newline" if nonl else "") + eol,
                    "[features]" + eol, "use_legacy_landlock = true" + eol],
            eol, blank_before=False)
    return lines


def parse(text):
    try:
        import tomllib
    except ImportError:
        return None
    try:
        return tomllib.loads(text)
    except Exception:
        return False


def check(mode, before, after):
    """Cross-check the edit with a real TOML parser when there is one."""
    old = parse(before)
    if old is None:
        return
    if old is False:
        raise Refuse("config.toml is not valid TOML; left as it is")
    new = parse(after)
    if new is False:
        raise Refuse("the edit would make config.toml invalid TOML")
    if mode == "keep":
        return
    if mode == "off":
        if new.get("sandbox_mode") != "danger-full-access":
            raise Refuse("the edit did not take effect (sandbox_mode)")
        for name, prof in (new.get("profiles") or {}).items():
            if isinstance(prof, dict) and "sandbox_mode" in prof \
                    and prof["sandbox_mode"] != "danger-full-access":
                raise Refuse("profile %r keeps its own sandbox_mode" % name)
    else:
        if (new.get("features") or {}).get("use_legacy_landlock") is not True:
            raise Refuse("the edit did not take effect (features.use_legacy_landlock)")
    # Nothing else may change.
    for key in set(old) | set(new):
        if key in ("sandbox_mode", "features", "profiles"):
            continue
        if old.get(key) != new.get(key):
            raise Refuse("the edit changed %r" % key)


def main(argv):
    if len(argv) != 2 or argv[1] not in ("off", "landlock", "keep"):
        sys.stderr.write("usage: inner-sandbox.py off|landlock|keep < config.toml > edited.toml\n")
        return 2
    mode = argv[1]
    before = sys.stdin.buffer.read().decode("utf-8", "surrogateescape")
    try:
        lines = restore(before.split("\n"))
        undone = "\n".join(lines)
        if mode == "off":
            lines = edit_off(lines)
        elif mode == "landlock":
            lines = edit_landlock(lines)
        after = "\n".join(lines)
        if mode == "keep" and after == before:
            pass        # nothing to undo: no reason to look at the file
        else:
            check(mode, before, after)
    except Refuse as e:
        sys.stderr.write("%s\n" % e)
        sys.stdout.buffer.write(before.encode("utf-8", "surrogateescape"))
        return 3
    sys.stdout.buffer.write(after.encode("utf-8", "surrogateescape"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
