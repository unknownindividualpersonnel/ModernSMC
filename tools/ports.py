#!/usr/bin/env python3
"""Find the bench's serial ports by USB identity, never by /dev/ttyACM number.

    python3 tools/ports.py            # what is plugged in, and what it is

/dev/ttyACM* numbers are assigned in enumeration order and move whenever
anything is replugged or reset. A run pointed at the wrong port does not fail —
it goes quiet and looks like dead hardware.

Discovery never writes to a port: the relay port executes single characters as
commands, so poking to identify would throw the line polarity. Identity comes
from the descriptor, via the `-ifNN` suffix in the by-id name.

Precedence, so a differently wired bench is never fought: an explicit
command-line argument wins, then the environment variable, then discovery.
"""
import glob
import os
import sys

BY_ID = "/dev/serial/by-id"

# (env var, by-id glob patterns, what it is).  Patterns are tried in order and
# the first that matches anything wins, so a specific name can precede a loose
# one without the loose one swallowing it.
ROLES = {
    "console": ("CONSOLE",
                ("*Debugprobe*-if01*",),
                "debug probe console (CDC 1)"),
    "polarity": ("POLARITY",
                 ("*Debugprobe*-if03*",),
                 "line-polarity relay (CDC 2)"),
    "modem": ("MODEM",
              ("*Conexant*Modem*", "*USB_Modem*", "*CX93*"),
              "far-end data modem (CX93001)"),
}


def _candidates(patterns):
    """by-id matches, deduped by the tty they resolve to."""
    seen, out = set(), []
    for pat in patterns:
        for link in sorted(glob.glob(os.path.join(BY_ID, pat))):
            real = os.path.realpath(link)
            if real in seen:
                continue
            seen.add(real)
            out.append(link)
        if out:
            break                       # first pattern that matches anything
    return out


def inventory():
    """Every by-id port, with the role it was recognized as (or None)."""
    rows = []
    for link in sorted(glob.glob(os.path.join(BY_ID, "*"))):
        role = None
        for name, (_, pats, _) in ROLES.items():
            if link in _candidates(pats):
                role = name
                break
        rows.append((link, os.path.realpath(link), role))
    return rows


def find(role, override=None, required=True):
    """Resolve one role to a device path.

    Returns a by-id path, not a /dev/ttyACM*, so the value stays correct if the
    device re-enumerates mid-session — and so anything that logs it records what
    it actually talked to rather than a number that means nothing tomorrow.
    """
    env, patterns, what = ROLES[role]
    if override:
        return override
    pinned = os.environ.get(env)
    if pinned:
        return pinned
    hits = _candidates(patterns)
    if len(hits) == 1:
        return hits[0]
    if not required:
        return None
    have = "\n".join(f"    {os.path.basename(link)} -> {real}"
                     + (f"   [{r}]" if r else "")
                     for link, real, r in inventory()) or f"    (nothing in {BY_ID})"
    if not hits:
        sys.exit(f"ports: no {role} found — {what}.\n"
                 f"  looked for {' or '.join(patterns)} in {BY_ID}\n"
                 f"  present:\n{have}\n"
                 f"  Plug it in, or pin it with {env}=/dev/serial/by-id/...")
    sys.exit(f"ports: {len(hits)} ports match {role} ({what}):\n"
             + "\n".join(f"    {h}" for h in hits)
             + f"\n  Pick one with {env}=...")


def same_device(a, b):
    """True when two port names are the same tty, whatever they are spelled as."""
    return bool(a) and bool(b) and os.path.realpath(a) == os.path.realpath(b)


def describe(path):
    """A short, stable name for a port, for logs."""
    real = os.path.realpath(path)
    for link in sorted(glob.glob(os.path.join(BY_ID, "*"))):
        if os.path.realpath(link) == real:
            return f"{os.path.basename(link)} ({real})"
    return real


def main():
    rows = inventory()
    if not rows:
        print(f"nothing in {BY_ID} — no USB serial devices are plugged in")
        return 1
    width = max(len(os.path.basename(p)) for p, _, _ in rows)
    print(f"{'by-id':<{width}}  {'device':<14}  role")
    for link, real, role in rows:
        print(f"{os.path.basename(link):<{width}}  {real:<14}  "
              + (role or "-"))
    print()
    for role, (env, _, what) in ROLES.items():
        got = find(role, required=False)
        pin = f"  [{env} is set]" if os.environ.get(env) else ""
        print(f"{role:<9} {what:<44} {got or 'NOT FOUND'}{pin}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
