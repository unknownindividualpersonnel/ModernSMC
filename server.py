#!/usr/bin/env python3
"""The far end of an SMC session: read the card's frames, answer them.

A whole session runs against this server on stock hardware -- a genuine Super
Mario Club cartridge in an unmodified adapter -- from login through the PIN
prompt to a content page that draws our own text.

WHAT A REPLY IS MADE OF
-----------------------
  * The card's login request is `REQ_LOGIN` ("0001"), built entirely from
    constants in bank 6 $8560 -- the serial "F343-7974-0001" at $FC6E and
    "NSM-02-00" at $FC53.  ($6000-$7FFF is the adapter's own built-in 8 KB
    W-RAM, not the card's SRAM, so nothing here depends on the slot.)
  * Bank 6 $8658 accepts the reply iff its data starts "0002" (`RESP_LOGIN_OK`).
    "0003" instead routes to $E530, the notice screen.
  * The rest of the reply's 35 bytes: [4:10] is unread on the login path, [10]
    is a challenge key for the next request, and [11:35] is Shift-JIS message
    text laid out on screen by $B60D (message.py).  The text is OURS -- it is
    not a reconstruction of what the original service sent.

Anything the card sends that is not in RULES gets no reply and a loud log line.
Guessing a response to an unrecognized request is exactly the trial-and-error
class this project has ruled out; the tool refuses rather than improvising.

THE PAGE FILE
-------------
WHAT is served lives in a page file, not here, and is RE-READ FROM DISK BEFORE
EVERY REPLY -- mid-call, without hanging up.  Edit it, save, then press B (目次)
on the Famicom: the card re-requests the same page and gets the new one.  A page
the card would reject is refused as it loads and the last good one keeps
serving, so a typo costs a log line rather than a re-dial.  PageSource below is
the whole mechanism -- no watcher, no thread, just a stat() and the same checks
--selftest runs.

Two page files ship, and --page picks between them:

    site_page.py   THE DEFAULT.  A whole service as a JSON tree in site/ --
                   menu, calendars, game records, search, questionnaires.
    page.py        --probe-page.  One page at a time, chosen by its own
                   EXPERIMENT =, for pinning down a widget or a header byte
                   on the bench.

USE
---
    python3 server.py --selftest        # offline, no hardware
    python3 server.py --check           # what would be served, offline
    python3 server.py --replay testdata/example.farend.bin

    python3 server.py --call --out captures/serve1.log
    #  the modem and the relay board are found by USB identity, not by
    #  /dev/ttyACM number -- those move, and a wrong one fails SILENTLY
    #  (tools/ports.py; $MODEM / $POLARITY pin them, --call PORT overrides)
    #  press ENTER as the card starts dialing -> second dial tone answers `W`
    #  the relays then throw BY THEMSELVES 1 s after the tone stops
    #  it runs until you press q -- NO CARRIER just re-arms for the next call

--call owns the modem for the whole session: manual ATA (keyed, because RING
has proven unreliable), automatic polarity reversal, the COM preamble, then the
responder.

--serve is the narrower mode: a port already in a data session, no dialing and
no relays.
"""
import argparse
import glob
import os
import sys
import threading
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tools"))
import content
import frame
import message
import ports

# `--call`/`--serve` with no value: resolve the port by USB identity instead.
AUTO = "auto"


class Framer:
    """Split the card's byte stream into frames.

    A card frame is <payload> <ck1> <ck2> and then EITHER $03 or $0D or both --
    which of them shows up is per-transaction, and getting this wrong cost a
    bench run:

        login   ($85D1)  ... 8e bd 0d      ETX suppressed, CR appended
        "0004"  ($87A0)  ... 8c c9 03      ETX only, NO CR AT ALL

    $F084 always writes the $03; the CR is extra, appended by bank 6 $85F0 when
    $6E20 == 0, and the "0004" sequencer simply has no such step.  A framer that
    waits for $0D therefore sees the "0004" request only when some later CRLF
    (NO CARRIER's) flushes it, by which time the line noise after the frame has
    been glued onto the end and the checksum no longer closes.

    So treat BOTH as terminators.  Neither can occur inside a frame: the
    payload is ASCII digits and the two checksum bytes always have bit 7 set.

    Leading junk is tolerated and reported, because there is some: both
    successful sessions carried a couple of $FF bytes on carrier before "COM"
    was sent, and a short burst after the frame.  They differ between runs
    (FF FF vs FF FF FF, and two different tails both ending 55 55), so they are
    line noise rather than protocol.  Hence no assumed length: every start
    offset is tried and the longest payload whose checksum closes is taken.
    """

    def __init__(self, log=None):
        self.buf = bytearray()
        self.log = log or (lambda m: None)
        self.junk = bytearray()

    def feed(self, chunk: bytes):
        """Absorb bytes; yield (payload, junk_before) for each closed frame."""
        self.buf += chunk
        while True:
            i = next((j for j, b in enumerate(self.buf)
                      if b in (0x03, 0x0D)), -1)
            if i < 0:
                return
            cand = bytes(self.buf[:i])
            del self.buf[:i + 1]
            body = cand[:-1] if cand.endswith(b"\x03") else cand
            hit = None
            for start in range(0, max(0, len(body) - 2) + 1):
                payload, ck = body[start:-2], body[-2:]
                if payload and frame.checksum(payload) == ck:
                    hit = (payload, body[:start])
                    break
            if hit is None:
                # The far-end port also carries the modem's own result codes
                # (OK / CONNECT 115200 / NO CARRIER) and the preamble we sent.
                # Those are text; anything else is a real anomaly.
                text = all(0x20 <= c < 0x7F or c in (0x0A, 0x09) for c in cand)
                if text:
                    s = cand.decode("ascii").strip()
                    if s:
                        self.log(f"-- {s}")
                elif cand:
                    self.log(f"!! {len(cand)}B before CR, no checksum closes: "
                             f"{cand.hex(' ')}")
                continue
            payload, junk = hit
            if junk:
                self.log(f"!! {len(junk)}B of junk before the frame: "
                         f"{junk.hex(' ')}")
            yield payload, junk


# --- the page file, and the checks it has to pass ----------------------------

# The site is the service; page.py is the bench dial, asked for by name.
DEFAULT_PAGE = os.path.join(HERE, "site_page.py")
PROBE_PAGE = os.path.join(HERE, "page.py")


def content_summary(block, card=None):
    """Bank 5's own view of a content block, as two log lines."""
    if block is None:
        return ["content: none -- the record goes out unterminated, so the "
                "card's own $03 takes",
                "| $FE7A's $03 branch: $6E80 = 0, $A847 draws the menu at once"]
    card = card or content.checker()
    r = card.check_content(block)
    walk = r["walk"]
    toks = " ".join(f"${l:02X}+{n}" for _, l, n in walk["tokens"]) if walk else ""
    return [f"content: header {r['header'].hex(' ') or '-'} | "
            f"stream {r['stream'].hex(' ') or '(empty)'}",
            f"| tokens {toks or '-'} -> "
            + (r["error"] or "bank 5 accepts; ends on the card's $03")]


def check_block(block, mod, card=None):
    """The card's own verdict on one content block.  Raises, or returns $80B7's
    measure result.

    Used both when a page file is loaded and again on the block page() actually
    returns for a request -- the two must not drift, because the second is the
    one that goes on the wire.
    """
    card = card or content.checker()
    bad = card.check_content(block)["error"]
    if bad is not None:
        raise ValueError(f"bank 5 rejects the content page: {bad}")
    m = card.measure(block)
    if m["error"] is not None:
        raise ValueError(f"the measure pass rejects the page: {m['error']}")
    want = getattr(mod, "INTERACTIVE", None)
    if want is not None and m["modeled"] and bool(want) != m["interactive"]:
        # This is now only a "the page is the shape you think it is" check.
        # It is NOT "the widgets work": measured 2026-08-09, a page with
        # interactive=False cycles on Left/Right perfectly well, because $B9
        # is already set when pass 5 ends.  What interactive=True really means
        # is that some alternative carries a nested-bracket sub-field -- and
        # that shape hung the card once (serve14), so the guard stays.
        raise ValueError(
            f"INTERACTIVE={want!r} but the page measures "
            f"interactive={m['interactive']} -- the $F1 cursor record and the "
            "arming disagree, so this does not go on the wire")
    return m


def check_page(mod):
    """Every offline check the card would run, over a whole page module.

    -> (problems, lines).  An empty `problems` means the card would accept
    everything this module can produce: each reply is built and card_verify()'d,
    the record goes through $AC67's grammar, the content blocks through $87AF /
    $881D / $88D0, and -- when a ROM image is present -- the page through the
    $80B7 measure pass as well.

    Each section is caught separately: a page file with a broken login message
    should still tell you what else is wrong.
    """
    problems, lines, card = [], [], content.checker()

    def check(name, fn):
        """Run one section.  fn returns its summary, or (summary, extra lines)."""
        try:
            out = fn()
        except Exception as exc:                                 # noqa: BLE001
            problems.append(f"{name.strip()}: {type(exc).__name__}: {exc}")
            return
        out, extra = out if isinstance(out, tuple) else (out, ())
        lines.append(f"{name:8}{out}")
        lines.extend(f"        {e}" for e in extra)

    def login():
        r = frame.build_login_reply(message=message.encode(mod.LOGIN_MESSAGE),
                                    key=mod.LOGIN_KEY)
        v = frame.card_verify(r)
        if v["error"]:
            problems.append(f"login: the card would reject the reply with "
                            f"{v['error']} at {v['where']}")
        _, info = message.layout(v["data"][frame.LOGIN_MSG_OFF:])
        if not info["terminated"]:
            problems.append("login: the message has no $5C $FE end marker, so "
                            "$B60D draws the block's padding after it")
        if info["rows_used"] > len(message.ROWS):
            problems.append(f"login: {info['rows_used']} rows of text and "
                            f"$B600 has {len(message.ROWS)}")
        return f"{len(r)}B, {info['rows_used']} row(s): {mod.LOGIN_MESSAGE}"

    def reject():
        r = frame.build_0004_retry(message=message.encode(mod.REJECT_MESSAGE))
        v = frame.card_verify(r)
        if v["error"]:
            problems.append(f'reject: the card would reject the "0006" reply '
                            f"with {v['error']} at {v['where']}")
        return f"{len(r)}B: {mod.REJECT_MESSAGE}"

    def menu():
        # _menu_record runs $AC67 and bank 5 over the record, and is what the
        # reply path itself calls -- so this checks the real thing.
        record, res = _menu_record(mod)
        blocks = frame.build_0004_blocks(record=record,
                                         trailer=mod.MENU_CONTENT or b"")
        v = frame.card_receive(blocks)
        if v["error"]:
            problems.append(f'menu: the card would reject the "0005" reply '
                            f"with {v['error']} at {v['where']}")
        elif not v["complete"]:
            problems.append('menu: the "0005" reply never closes its message')
        size = sum(len(b) for b in blocks)
        blk = f" in {len(blocks)} blocks" if len(blocks) > 1 else ""
        return (f'"0005" {size}B{blk}, {res["entries"]} entr(ies), '
                f'{len(res["buffers"]["pages"])} content page(s)',
                content_summary(mod.MENU_CONTENT, card))

    def page():
        # req = None is the preview call; see page.py's contract.
        block = mod.page(None)
        m = check_block(block, mod, card)     # raises -> reported by check()
        blocks = frame.build_page_blocks(block)
        v = frame.card_receive(blocks)
        if v["error"]:
            problems.append(f'page: the card would reject the "13" reply with '
                            f"{v['error']} at {v['where']}")
        elif not v["complete"]:
            problems.append('page: the "13" reply never closes its message')
        size = f"{sum(len(b) for b in blocks)}B"
        if len(blocks) > 1:
            size += f" in {len(blocks)} blocks"
        if not m["modeled"]:
            return f'"13" {size}, fields not measured (no ROM image)', \
                content_summary(block, card)
        kinds = ",".join(sorted({f["kind"] for f in m["fields"]})) or "-"
        return (f'"13" {size}, {len(m["fields"])} field(s) [{kinds}], '
                f'interactive={m["interactive"]}',
                content_summary(block, card))

    def site():
        # A site module validates its WHOLE page tree, not just the preview
        # block page() covered above.
        probs = mod.check_all()
        problems.extend(f"site: {p}" for p in probs)
        return f"check_all: {len(probs)} problem(s)" if probs else \
            "check_all: every node clean"

    check("login   ", login)
    check("reject  ", reject)
    check("menu    ", menu)
    check("page    ", page)
    if hasattr(mod, "check_all"):
        check("site    ", site)
    return problems, lines


class PageSource:
    """page.py, read ON DEMAND -- and checked before it counts.

    This is the reason the bench loop no longer needs a restart.  The card
    re-requests its page every time B (目次) is pressed, so the far end is free
    to answer with something different each time; all that is needed is to
    re-read the file when a request arrives, which costs about a millisecond
    (check_page() included -- the ROM emulator is fast on blocks this small).

    No watcher and no thread: current() is called from the reply path, and the
    stat() in poll() only decides whether re-executing the file is worth it.
    Its other job is to keep the session log honest -- `page reloaded` appears
    exactly when the content actually changed, which is what a capture needs.

    A file that fails check_page() is NOT adopted: `mod` keeps pointing at the
    last good version and the errors go to the log.  Nothing is lost by that --
    the card will ask again -- whereas serving a bad page costs a re-dial, and
    one shape of bad page has hung the card.
    """

    def __init__(self, path=None, log=None):
        self.path = path or DEFAULT_PAGE
        self.log = log or (lambda m: None)
        self.mod = None                 # the last GOOD module
        self.gen = 0                    # bumped on every adoption
        self.error = None               # why the file on disk is not serving
        self._seen = None               # the stamp we last looked at
        self.watch = []                 # the adopted module's WATCH globs

    def _stamp(self):
        # One tuple over the page file AND everything WATCH matches, so a data
        # file edited mid-call (or added, or deleted) reloads like the page.
        files = [self.path]
        for pat in self.watch:
            files.extend(sorted(glob.glob(pat, recursive=True)))
        stamps = []
        for f in files:
            try:
                st = os.stat(f)
            except OSError as exc:                               # noqa: BLE001
                stamps.append((f, "unreadable", str(exc)))
            else:
                stamps.append((f, st.st_mtime_ns, st.st_size))
        return tuple(stamps)

    def _exec(self):
        """Compile and execute the file into a FRESH module object.

        Not importlib.reload(): a file with a syntax error must not be able to
        damage the module we are currently serving, and reload() mutates it in
        place.  Nothing goes into sys.modules either, so a half-written file
        caught mid-save is simply discarded.

        And not importlib's file loader either, which is the subtler trap and
        cost a debugging session: it validates its __pycache__ entry against
        the source's mtime **in whole seconds** plus its size, so editing one
        character within a second of the last load re-executes the OLD
        BYTECODE and the server serves the previous page while reporting a
        reload.  Change a katakana glyph for another and both stay true.
        Reading the source and compile()ing it has no cache to be stale.
        """
        with open(self.path, encoding="utf-8") as f:
            src = f.read()
        mod = types.ModuleType("smc_page_live")
        mod.__file__ = self.path
        exec(compile(src, self.path, "exec"), mod.__dict__)      # noqa: S102
        for name in ("LOGIN_MESSAGE", "LOGIN_KEY", "REJECT_MESSAGE",
                     "MENU_ENTRIES", "MENU_CONTENT", "page"):
            if not hasattr(mod, name):
                raise AttributeError(f"the page file defines no {name}")
        return mod

    def reload(self):
        """Read, check, and adopt if clean.  -> True if a new version is live."""
        self._seen = self._stamp()
        try:
            mod = self._exec()
            problems, lines = check_page(mod)
        except Exception as exc:                                 # noqa: BLE001
            mod, lines = None, []
            problems = [f"{type(exc).__name__}: {exc}"]
        who = os.path.relpath(self.path, HERE)
        if who.startswith(".."):                # a --page outside the repo
            who = self.path
        if problems:
            self.error = problems[0]
            self.log(f"!! {who} NOT adopted:")
            for p in problems:
                self.log(f"!!   {p}")
            self.log("!! still serving " + (f"generation {self.gen}"
                                            if self.mod else "NOTHING"))
            return False
        # A site module keeps its navigation in SESSION_STATE; carry it so a
        # mid-call edit does not throw the user back to the menu.
        old = getattr(self.mod, "SESSION_STATE", None)
        new = getattr(mod, "SESSION_STATE", None)
        if isinstance(old, dict) and isinstance(new, dict):
            new.update(old)
        self.mod, self.error = mod, None
        self.watch = list(getattr(mod, "WATCH", []))
        self._seen = self._stamp()      # re-stat under the adopted WATCH list
        self.gen += 1
        self.log(f"## page reloaded: {who}, generation {self.gen}")
        for line in lines:
            self.log(f"##   {line}")
        return True

    def poll(self, force=False):
        """One stat(), and a reload only if the file moved.  -> True if a new
        version went live."""
        if not force and self._stamp() == self._seen:
            return False
        return self.reload()

    def current(self):
        """The module to serve from: the file as it stands right now."""
        self.poll()
        if self.mod is None:
            raise RuntimeError(f"{self.path} does not load: {self.error}")
        return self.mod


# The one instance the builders below read.  --page repoints it; --call and
# --serve give it their own logger so reloads carry session timestamps.
PAGES = PageSource()


# Request code -> how to answer.  Each entry is (name, builder(data) -> bytes
# or None).  Deliberately sparse: see the module docstring.
def _login(data: bytes) -> bytes:
    p = PAGES.current()
    return frame.build_login_reply(
        message=message.encode(p.LOGIN_MESSAGE), key=p.LOGIN_KEY)


def _auth_0004(data: bytes, log) -> None:
    """Decode the "0004" request and check it against the $FC7E model.

    The card sends the member number in the clear plus four digits mixed from
    it and the PIN, so with the key we chose the PIN can be recovered exactly.
    If the recovered PIN is not the one that was typed, the model is wrong --
    this is the test, not a convenience.
    """
    parts = frame.split_0004(data)
    if parts is None:
        log(f"!! \"0004\" request is {len(data)}B, expected 22 -- not decoding")
        return
    _, member, digits = parts
    buf10 = b"00" + member
    key = PAGES.current().LOGIN_KEY[0] & 0x0F
    pin = frame.recover_pin(buf10, digits, key)
    log(f"   member number : {member.decode('ascii', 'replace')}")
    log(f"   auth digits   : {digits.decode('ascii', 'replace')}")
    log(f"   -> implied PIN: {pin.decode('ascii', 'replace')}  "
        f"(key {key}; $FC7E inverted)")
    check = frame.auth_digits(buf10, pin, key)
    log(f"   round-trip    : {'OK' if check == digits else 'MISMATCH'}")
    log("   ** compare that PIN with what you typed at 暗証番号. If it "
        "matches, $FC7E is confirmed on hardware.")


# What to answer "0004" with.  "0005" accepts and moves on to $A800; "0006"
# rejects, draws the page file's REJECT_MESSAGE and returns to the PIN prompt.
# Set by --reject; it is a mode of the server, not content, so it stays here.
REJECT_PIN = False

# Seconds between the blocks of a multi-block reply.  CPU2 delimits blocks on
# $03 alone ($8A = $03, $8E = $00 -- no inter-character flush), so two blocks
# sent back to back are two chunks of one stream, and nothing in the ROM says
# the card must have finished with the first before the second lands.  A gap
# costs nothing and takes that variable out of the first bench attempt; set it
# to 0 to test the other case deliberately.
BLOCK_GAP = 0.25


def _menu_record(p):
    """Build the menu, and run the card's own parser and bank-5 validator
    over it before any of it goes on the wire."""
    # MENU_CONTENT = None asks for the record page straight after the PIN:
    # the record goes out unterminated and the card's own $03 takes the $FE89
    # branch.  Anything else is the $04 branch and needs a trailer to land on.
    term = None if p.MENU_CONTENT is None else content.EOT
    record = content.build_record(p.MENU_ENTRIES, term=term)
    card = content.checker()
    # The parser needs to see the terminator the card will see.
    res = card.parse(record if term is not None else record + bytes([content.ETX]))
    if res["error"] is not None:
        raise ValueError(f"$AC67 rejects this menu with {res['error']}")
    if p.MENU_CONTENT is not None:
        bad = card.check_content(p.MENU_CONTENT)["error"]
        if bad is not None:
            raise ValueError(f"bank 5 rejects the content block: {bad}")
    return record, res


def _auth_reply(data: bytes):
    p = PAGES.current()
    if REJECT_PIN:
        return frame.build_0004_retry(message=message.encode(p.REJECT_MESSAGE))
    record, _ = _menu_record(p)
    # A list of unpadded blocks: one when the record fits, more when it does
    # not.  Reassembly at $6100 precedes $AC67, so a split menu is legal.
    return frame.build_0004_blocks(record=record,
                                   trailer=p.MENU_CONTENT or b"")


def _page_reply(data: bytes) -> bytes:
    """Ask the page file what to draw, and re-check what it hands back.

    page() gets the parsed request, so it may answer differently each time --
    which means the check_page() run at load time does NOT cover this block.
    Run the card's checks over the actual bytes.
    """
    p = PAGES.current()
    block = p.page(frame.split_request(data))
    check_block(block, p)
    # One block if it fits, otherwise as many as it takes: $EF32 appends each
    # one at $6E29/$6E2A and $F3F8 writes the stream's $03 after the last, so
    # bank 5 sees exactly these bytes either way, and a boundary may fall
    # anywhere -- mid-token, mid-word.  What is untested is the PACING: the
    # blocks go out BLOCK_GAP apart and back-to-back has never been tried.
    return frame.build_page_blocks(block)


RULES = {
    frame.REQ_LOGIN: ("login (bank 6 $8560/$85D1)", _login),
    frame.REQ_0004: ("0004 auth (bank 6 $8738)", _auth_reply),
    frame.REQ_PAGE: ('"13" page (bank 2 $B326 -> $F374)', _page_reply),
}


class Session:
    """Frames in, replies out.  No I/O, so it is testable offline."""

    def __init__(self, log=None, rules=None):
        self.log = log or (lambda m: None)
        self.rules = RULES if rules is None else rules
        self.framer = Framer(self.log)
        self.seen = []
        # Reloads are session events -- they belong in this session's log, with
        # its timestamps, next to the frame that triggered them.
        PAGES.log = self.log

    def feed(self, chunk: bytes):
        for payload, _junk in self.framer.feed(chunk):
            yield from self._handle(payload)

    def _handle(self, payload: bytes):
        hdr, data, declared, consistent = frame.split_payload(payload)
        code = frame.request_key(data)
        self.seen.append((hdr, data))
        self.log(f"<< frame {len(payload)}B  hdr={hdr.decode('ascii', 'replace')} "
                 f"declared={declared} ({'ok' if consistent else 'MISMATCH'}) "
                 f"code={code.decode('ascii', 'replace')!r}")
        self.log(f"   data {data.decode('ascii', 'replace')}")
        req = frame.split_request(data)
        if req is not None:
            # data[0:4] is '1' + the page number, not a request code -- see the
            # $F374 layout in frame.py.  Spell the fields out so a capture
            # is readable without going back to the ROM.
            self.log(f"   $F374 request: section {req['section'].decode()!r} "
                     f"command {req['command'].decode()!r} payload "
                     f"{req['payload'].hex(' ')} "
                     f"({req['payload'].decode('ascii', 'replace')})")
        rule = self.rules.get(code)
        if rule is None:
            self.log(f"!! no rule for request {code!r} -- staying silent. "
                     "The card will time out with 4300 ($F110 budget). "
                     "Add a rule only from the ROM, never by guessing.")
            return
        name, build = rule
        if code == frame.REQ_0004:
            _auth_0004(data, self.log)
        try:
            reply = build(data)
        except Exception as exc:                                 # noqa: BLE001
            # A builder raising is normal now that the content is edited live:
            # a bad page file, or a page() that blows up on this request.  The
            # card times out and asks again, so a live call survives a typo.
            self.log(f"!! {name}: {type(exc).__name__}: {exc}")
            self.log("!! staying silent -- fix it and let the card re-request "
                     "(B / 目次), no need to hang up.")
            return
        if reply is None:
            self.log(f"!! {name}: staying silent. The card will time out with "
                     "4300 ($F110 budget) -- expected until the reply is read "
                     "out of the ROM.")
            return
        # A rule may answer with one block or with a list of them.  $ED6E
        # reseeds BOTH $6E48 and the $6E29/$6E2A write pointer for every
        # request it sends, so each message starts first-block, sequence '0'.
        blocks = [reply] if isinstance(reply, (bytes, bytearray)) else list(reply)
        v = frame.card_receive(blocks)
        if v["error"]:
            self.log(f"!! refusing to send: the card would reject this with "
                     f"{v['error']} at {v['where']}")
            return
        if not v["complete"]:
            self.log("!! refusing to send: the last block does not close the "
                     "message ($EDEF goes back to $ED9D), so the card would "
                     "wait for another and time out at 4300")
            return
        if len(blocks) > 1:
            self.log(f">> {name}: {len(blocks)} blocks, {len(v['data'])}B "
                     f"assembled at ${frame.WRAM_IN:04X}..${v['ptr']:04X}  "
                     + " ".join(f"[{b['cont']}{b['seq']}:{len(x) - 13}B]"
                                for b, x in zip(v["blocks"], blocks)))
        for reply in blocks:
            # The block is not a fixed 48 bytes -- the "0005" reply is unpadded
            # -- so index the checksum and ETX from the end, not from 45/47.
            self.log(f">> {name}: {len(reply)}B  hdr={reply[:10].decode()} "
                     f"data={reply[10:20].decode('ascii', 'replace')}"
                     f"[{reply[20:-3].hex(' ')}] ck={reply[-3:-1].hex(' ')} "
                     f"etx={reply[-1]:02X}")
        self._describe(code, v["data"])
        yield from blocks

    def _describe(self, code, data):
        """Show what the CARD will make of the reply's payload.

        Which routine consumes it depends on the reply, so this has to branch:
        a message goes through $B60D and can be rendered, a record goes through
        $AC67 and cannot.  Laying out a record as if it were text produces
        confident nonsense, which is worse than nothing.
        """
        msg_off = None
        if code == frame.REQ_LOGIN:
            msg_off = frame.LOGIN_MSG_OFF          # $610B, via $86AC
        elif code == frame.REQ_0004 and REJECT_PIN:
            msg_off = 10                               # $610A, via $8896
        if msg_off is not None:
            # An unterminated stream is a real (if survivable) defect -- say so
            # here rather than discovering it on screen.
            rec, info = message.layout(data[msg_off:])
            self.log(f"   message: {info['reason']}, {info['rows_used']} row(s)")
            for line in message.describe(rec).splitlines():
                self.log(f"   | {line}")
            return
        if code == frame.REQ_0004:
            record = data[10:]
            end = next((i for i, b in enumerate(record) if b in (0x03, 0x04)),
                       None)
            # No terminator in the data is the INTENDED form, not a fault:
            # $F3F8 writes the card's own $03 one byte past the block, which is
            # exactly where $ACDD looks, and $FE7A's $03 branch draws the
            # record page at once with $6E80 = 0.  Parse it the way the card
            # will see it.
            naked = end is None
            if naked:
                record += bytes([0x03])
                end = len(record) - 1
            # Run the card's own parser over what we are about to send, and
            # report the four-digit code it would show.  This is the same
            # check card_verify() does for the frame, one layer up.
            card = content.checker()
            res = card.parse(record[:end + 1])
            if res["error"] is not None:
                self.log(f"   !! $AC67 would reject this record: "
                         f"error {res['error']}")
                return
            lines = res["buffers"]["lines"]
            self.log(f"   record: {res['entries']} entr(ies), terminator "
                     + ("the card's own $03 -> $A847, straight to the menu"
                        if naked else
                        f"${record[end]:02X} -> bank 5's content stream")
                     + f", {len(res['buffers']['pages'])} content page(s)")
            for i in range(res["entries"]):
                text = content._sjis(lines[i * 22:(i + 1) * 22])
                self.log(f"   | {i}: {text}")
            # Bank 5 reads its own header block from just past the terminator
            # -- but only on the $04 path; the $03 branch never goes there.
            if not naked:
                self._describe_content(record[end + 1:], card)
            return
        if code == frame.REQ_PAGE:
            action = frame.page_action(data)
            self.log(f"   $A03C: code {data[:4].decode('ascii', 'replace')!r} "
                     f"sub {data[4:6].decode('ascii', 'replace')!r} -> index "
                     f"{action} = {frame.PAGE_HANDLERS[action]}")
            if action != 0:
                return
            self._describe_content(data[frame.PAGE_BODY_OFF:])

    def _describe_content(self, block, card=None):
        """Run bank 5's own header + stream checks over a content page.

        `block`, not `content`: the module is called that now, and a parameter
        of the same name would shadow it.
        """
        for line in content_summary(block, card):
            self.log(f"   {line}")


def replay(path: str, quiet: bool = False) -> int:
    def log(m):
        if not quiet:
            print(m)

    sess = Session(log)
    raw = open(path, "rb").read()
    # Strip the modem's own result codes: the capture is everything the far end
    # port produced, CONNECT/NO CARRIER included.
    replies = list(sess.feed(raw))
    log(f"-- {len(sess.seen)} frame(s), {len(replies)} reply(ies)")
    return replies


_FIXTURE = '''
import sys
sys.path.insert(0, %r)
import content
LOGIN_MESSAGE = "ようこそ"
LOGIN_KEY = b"0"
REJECT_MESSAGE = "ばんごう"
MENU_ENTRIES = [{"name": 0x81, "items": [(0x81, 0x7F)]}]
MENU_CONTENT = content.build_content(content.text_token("M", col=5, row=12))
INTERACTIVE = False
def page(req):
    return content.build_content(content.text_token(%r, col=5, row=12))
'''


def _reload_case():
    """A one-character edit, same second, same size -- served or not?

    This is the case importlib's file loader gets WRONG: its __pycache__ entry
    is validated against the source mtime in **whole seconds** plus the size,
    so re-executing the file gives the previous bytecode and the server serves
    the old page while logging a reload.  Editing one glyph and pressing B is
    the normal way to use this thing, so it is guarded here rather than left to
    be rediscovered on the bench.
    """
    import tempfile
    keep_path, keep_mod, keep_seen = PAGES.path, PAGES.mod, PAGES._seen
    quiet, PAGES.log = PAGES.log, lambda m: None
    try:
        with tempfile.TemporaryDirectory() as tmp:
            PAGES.path = os.path.join(tmp, "case.py")
            out = []
            for text in ("AAA", "BBB"):            # same length, no pause
                with open(PAGES.path, "w", encoding="utf-8") as f:
                    f.write(_FIXTURE % (HERE, text))
                PAGES._seen = None                 # the stat is not what is
                PAGES.reload()                     # under test here
                out.append(PAGES.mod.page(None))
            return b"AAA" in out[0] and b"BBB" in out[1]
    finally:
        PAGES.path, PAGES.mod, PAGES._seen = keep_path, keep_mod, keep_seen
        PAGES.log = quiet


def selftest() -> int:
    here = os.path.join(HERE, "testdata")
    cap = os.path.join(here, "polarity_dle300.farend.bin")
    ok = True

    print("== replay of a recorded session ==")
    if not os.path.exists(cap):
        print(f"FAIL: {cap} is missing -- it ships with the repo")
        return 1
    sess = Session(print)
    replies = list(sess.feed(open(cap, "rb").read()))

    one_frame = len(sess.seen) == 1
    print("frames   :", "PASS" if one_frame else f"FAIL ({len(sess.seen)})",
          "(the session carried exactly one card frame)")

    hdr, data = sess.seen[0] if sess.seen else (b"", b"")
    login_ok = data == b"0001000000F3437974000100200"
    print("login    :", "PASS" if login_ok else "FAIL",
          "(matches bank 6 $8560's ROM constants)")

    replied = len(replies) == 1
    print("answered :", "PASS" if replied else "FAIL")

    accepted = False
    if replied:
        r = replies[0]
        v = frame.card_verify(r)
        accepted = (len(r) == frame.REPLY_LEN and v["error"] is None
                    and v["action"] == 0
                    and v["data"][:4] == frame.RESP_LOGIN_OK)
        print(f"reply    : {len(r)}B error={v['error']} action={v['action']} "
              f"data[0:4]={v['data'][:4]!r}")
    print("accepted :", "PASS" if accepted else "FAIL")

    # The message must end on its own $5C $FE, not run into the padding.
    msg_ok = False
    if replied:
        _, info = message.layout(
            frame.card_verify(replies[0])["data"][frame.LOGIN_MSG_OFF:])
        msg_ok = info["terminated"] and info["rows_used"] <= len(message.ROWS)
        print(f"message  : {info}")
    print("message  :", "PASS" if msg_ok else "FAIL")

    # Both "0004" answers must build and pass the card's own checks.  The
    # reject path is the one that can silently outgrow its block: its message
    # shares the 35 data bytes with a 10-byte prefix, so a string that fits the
    # login reply need not fit here.  The accept path is deliberately UNPADDED
    # -- the card writes the content stream's $03 right after our last byte --
    # so it is checked against the 48-byte block, not equal to it.
    print()
    print("== both \"0004\" answers ==")
    global REJECT_PIN
    both_ok = True
    for reject, what in ((False, '"0005" accept'), (True, '"0006" reject')):
        REJECT_PIN = reject
        try:
            r = _auth_reply(b"0004000000" + b"1" * 12)
            blocks = [r] if isinstance(r, (bytes, bytearray)) else list(r)
            v = frame.card_receive(blocks)
            # Blocks are variable-length -- CPU2 is ETX-terminated for SMC and
            # caps at 252 ($8F = $FC).  48 was only ever a convenient default.
            good = (v["error"] is None and v["complete"]
                    and all(len(b) <= 252 for b in blocks))
            if not reject:
                # The stream must land exactly on the $03 the card appends,
                # which follows the LAST block's data.
                menu = PAGES.current().MENU_CONTENT
                last = blocks[-1]
                if menu is None:
                    # Unterminated: the last data byte is the record's own
                    # final '/', and the card's $03 goes one past it.
                    good &= last[-4:-3] == b"/"
                else:
                    good &= content.checker().check_content(menu)["error"] is None
                    good &= last[-4:-3] == menu[-1:]
            size = sum(len(b) for b in blocks)
            print(f"  {what:16} {size}B in {len(blocks)} block(s) "
                  f"error={v['error']} data={v['data'][:10].decode()}...")
        except Exception as exc:                             # noqa: BLE001
            good = False
            print(f"  {what:16} FAILED to build: {exc}")
        both_ok &= good
    REJECT_PIN = False

    # A menu grown past one block, end to end: split by build_0004_blocks,
    # reassembled by the card's receive path, and the RESULT through the real
    # $AC67.  If $EF32's concatenation is invisible to the record parser, this
    # passes for the same reason the one-block menu does.  Probe P2 is the
    # hardware half of the claim.
    entries = [{"name": b"%-16d" % i,
                "items": [(content.submenu_record("%03d" % (101 + i * 8 + j),
                                                  "LINE %d.%d" % (i, j)), 0x7F)
                          for j in range(3)]}
               for i in range(7)]
    rec5 = content.build_record(entries, term=None)
    blocks5 = frame.build_0004_blocks(record=rec5)
    v5 = frame.card_receive(blocks5)
    res5 = content.checker().parse(v5["data"][10:] + bytes([content.ETX]))
    menu5_ok = (len(blocks5) > 1 and v5["error"] is None and v5["complete"]
                and v5["data"][10:] == rec5 and res5["error"] is None
                and res5["entries"] == 7)
    print(f'  split "0005"    {len(rec5)}B record -> {len(blocks5)} blocks '
          f"error={v5['error']} $AC67={res5['error'] or 'accepts'} "
          f"entries={res5['entries']}")
    both_ok &= menu5_ok
    print("replies  :", "PASS" if both_ok else "FAIL")

    # The '1' family.  The exact 11 data bytes serve9 caught on the menu page,
    # and the page we answer with, run through bank 5's own checks.
    print()
    print('== the "13" page request ==')
    req = b"1000130000M"
    key_ok = frame.request_key(req) == frame.REQ_PAGE
    parts = frame.split_request(req)
    print(f"  key {frame.request_key(req)!r} section {parts['section']!r} "
          f"command {parts['command']!r} payload {parts['payload']!r}")
    print("  key      :", "PASS" if key_ok else "FAIL",
          "($F374: '1' + section + command + \"0000\")")
    # $EE9C's family shares the "13" command but not the layout, and must not
    # collide: its data[6:10] is "2000", not "0000".
    other_family = frame.request_key(b"1abc132000x") != frame.REQ_PAGE
    print("  $EE9C    :", "PASS" if other_family else "FAIL",
          "('1' + 3 + \"132000\" is a different request, not this one)")
    page_blocks = _page_reply(req)
    pv = frame.card_receive(page_blocks)
    body = pv["data"][frame.PAGE_BODY_OFF:]
    cr = content.checker().check_content(body)
    block = PAGES.current().page(frame.split_request(req))
    page_ok = (pv["error"] is None and pv["complete"]
               and frame.page_action(pv["data"]) == 0
               and cr["error"] is None
               and page_blocks[-1][-4:-3] == block[-1:])
    print(f"  reply {sum(len(r) for r in page_blocks)}B in "
          f"{len(page_blocks)} block(s) error={pv['error']} "
          f"$A03C index={frame.page_action(pv['data'])} "
          f"bank5={cr['error'] or 'accepts'}")
    print("  page     :", "PASS" if page_ok else "FAIL",
          "($A03C -> bank 5 $8000 -> $80B7, stream ends on the card's $03)")
    # $8000 reads $610A before anything else and an $Ax high nibble hangs up.
    hangup_ok = False
    try:
        frame.build_page_reply(b"\xa0\x80")
    except ValueError as exc:
        hangup_ok = "hang up" in str(exc)
    print("  $Ax guard:", "PASS" if hangup_ok else "FAIL")

    # A page too big for one block, all the way through: split by
    # build_page_blocks, reassembled by the card's own receive path, and the
    # RESULT handed to bank 5.  If $EF32's concatenation is really invisible to
    # $881D/$88D0, this passes for exactly the same reason the one-block page
    # does -- and if it is not, this is where we find out, not on the wire.
    big = content.build_content(
        content.para_token(
            "THE CONTENT STREAM IS ASSEMBLED FROM AS MANY BLOCKS AS IT TAKES. "
            "EACH ONE IS APPENDED AT THE RUNNING POINTER AND THE CARD WRITES "
            "THE TERMINATOR AFTER THE LAST. NOTHING LOOKS AT THE BYTES UNTIL "
            "THEN, SO A BLOCK BOUNDARY MAY FALL ANYWHERE AT ALL.",
            col=4, row=5, width=23, height=8, wrap=True))
    big_blocks = frame.build_page_blocks(big)
    bv = frame.card_receive(big_blocks)
    bcard = content.checker()
    bbody = bv["data"][frame.PAGE_BODY_OFF:]
    bchk = bcard.check_content(bbody)
    bmeas = bcard.measure(bbody)
    split_ok = (len(big_blocks) > 1 and bv["error"] is None and bv["complete"]
                and bbody == big and bchk["error"] is None
                and bmeas["error"] is None)
    print(f"  split {len(big)}B page -> {len(big_blocks)} blocks "
          f"{[(b['cont'], b['seq']) for b in bv['blocks']]} "
          f"-> ${frame.WRAM_IN:04X}..${bv['ptr']:04X} "
          f"error={bv['error']} bank5={bchk['error'] or 'accepts'} "
          f"panes={bmeas['c3'] & 0x7F if bmeas['modeled'] else '?'}")
    print("  multiblk :", "PASS" if split_ok else "FAIL",
          "(reassembled bytes identical, and bank 5 takes them)")

    page_ok &= key_ok and other_family and hangup_ok and split_ok
    print('"13"     :', "PASS" if page_ok else "FAIL")

    # The page file, through the same checks a mid-call reload runs.  This is
    # the regression guard on the whole served surface: if editing page.py can
    # break the session, it breaks here first.
    print()
    print("== the page file ==")
    problems, lines = check_page(PAGES.current())
    for line in lines:
        print("  " + line)
    for p in problems:
        print("  !! " + p)
    pages_ok = not problems
    print("page file:", "PASS" if pages_ok else "FAIL",
          f"({os.path.relpath(PAGES.path, HERE)})")

    # And a broken page file must NOT take the last good one down with it.
    keep = PAGES.mod
    PAGES.path, PAGES._seen = os.path.join(HERE, "does-not-exist.py"), None
    kept = PAGES.poll() is False and PAGES.mod is keep
    PAGES.path, PAGES._seen = DEFAULT_PAGE, None
    print("fallback :", "PASS" if kept else "FAIL",
          "(an unloadable page file leaves the last good one serving)")
    fresh = _reload_case()
    print("re-read  :", "PASS" if fresh else "FAIL",
          "(a same-second, same-size edit is really re-executed, not cached)")
    pages_ok &= kept and fresh

    # An unknown request must produce silence, not a guess.  Use a code no
    # rule claims -- "0004" is answered now, so it no longer tests this.
    print()
    print("== an unrecognized request ==")
    other = frame.encode_data(b"9999000000" + b"0" * 12)
    quiet = Session(print)
    got = list(quiet.feed(other))
    silent = got == []
    print("silence  :", "PASS" if silent else "FAIL",
          "(no rule -> no reply, by design)")

    # The SECOND successful session.  Same payload, different line noise
    # (FF FF vs FF FF FF before, a different tail after) -- which is how we
    # know neither is a protocol field.  It also proves the framer does not
    # depend on the junk being a fixed length.
    print()
    print("== the second session ==")
    cap2 = os.path.join(here, "example.farend.bin")
    second = False
    if os.path.exists(cap2):
        s2 = Session(lambda m: None)
        r2 = list(s2.feed(open(cap2, "rb").read()))
        second = (len(s2.seen) == 1 and len(r2) == 1
                  and s2.seen[0] == sess.seen[0] and r2[0] == replies[0])
        print(f"payload identical to the first run: {s2.seen[0][1] == data}")
    print("second   :", "PASS" if second else "FAIL")

    ok = all([one_frame, login_ok, replied, accepted, msg_ok, both_ok,
              page_ok, pages_ok, silent, second])
    print()
    print("selftest :", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# --- the bench ---------------------------------------------------------------
#
# Answer the card's call, get to data mode, then run the responder.
#
#   * ATA stays MANUAL.  Waiting for RING has proven unreliable -- the line
#     simulator does not pass it through at all -- so a keypress starts it.
#   * The polarity flip is AUTOMATIC, one second after the 400 Hz repeater
#     stops.  Its timing is not a judgment call: `g` gives 32.5 s from the last
#     digit, so the flip wants to land as soon as the tone that answered `W`
#     is done.

SDT_DEFAULTS = {"freq": 400, "on": 8, "off": 12, "cycles": 36}


class Call:
    """Drive one call from off-hook to teardown, answering the card's frames."""

    def __init__(self, port, sess, log, polarity=None, sdt=None, s7=30,
                 polarity_delay=1.0, com_delay=1.0, rawlog=None):
        import serial
        self.m = serial.Serial(port, 115200, timeout=0.2)
        self.sess, self.log, self.rawlog = sess, log, rawlog
        self.polarity, self.sdt, self.s7 = polarity, sdt or SDT_DEFAULTS, s7
        self.polarity_delay, self.com_delay = polarity_delay, com_delay
        self.t0 = time.time()
        self.connected_at = self.tone_done_at = self.no_carrier_at = None
        self.thrown = self.handed_over = self.com_sent = False
        self.manual = None
        self.stop_flag = False

    def say(self, text):
        self.log(f"[{time.time() - self.t0:8.3f}] {text}")

    def _at(self, cmd, secs=6.0):
        """One AT command.  The 5 ms poll is deliberate: the 200 ms main-loop
        timeout quantises every reading, and +VTS is timed by the modem, so
        elapsed time is the only evidence a tone list actually played."""
        prev, self.m.timeout = self.m.timeout, 0.005
        try:
            self.m.reset_input_buffer()
            self.m.write((cmd + "\r").encode())
            self.m.flush()
            t0, out = time.time(), b""
            while time.time() - t0 < secs:
                c = self.m.read(64)
                if c:
                    out += c
                    if out.rstrip().endswith((b"OK", b"ERROR", b"NO CARRIER")):
                        break
                else:
                    time.sleep(0.002)
            rep, dt = out.decode("ascii", "replace").strip(), time.time() - t0
        finally:
            self.m.timeout = prev
        self.say(f"> {cmd}   ({dt:.3f}s) -> {rep!r}")
        return rep, dt

    def sdt_sequence(self, why, ata=False):
        """NTT's second dial tone, which is what answers the `W` wait opcode."""
        cfg = self.sdt
        self.say(f"# second-dial-tone sequence ({why})")
        rep, _ = self._at("AT+FCLASS=8")
        if "OK" not in rep:
            self.say("!! no voice mode; falling back to a plain ATA")
            self._at("AT+FCLASS=0")
            return self.handover("no voice mode")
        rep, _ = self._at("AT+VLS=1")
        if "OK" not in rep:
            self.say("!! AT+VLS=1 refused, cannot go off-hook in voice mode")
            self._at("AT+FCLASS=0")
            return self.handover("no off-hook in voice mode")

        on, off = cfg["on"], cfg["off"]
        tone, gap = f"[{cfg['freq']},0,{on}]", f"[0,0,{off}]"
        per_chunk = 3                       # +VTS truncates at ~790 ms
        chunks = -(-cfg["cycles"] // per_chunk)
        played = 0.0
        for i in range(chunks):
            n = min(per_chunk, cfg["cycles"] - i * per_chunk)
            want = n * (on + off) / 100.0
            rep, dt = self._at("AT+VTS=" + ",".join([tone, gap] * n),
                               secs=want + 4.0)
            played += dt
            if "OK" not in rep:
                self.say(f"!! +VTS rejected ({rep!r}); cadence incomplete")
                break
            if dt < 0.7 * want:
                self.say(f"!! +VTS chunk {i} returned in {dt:.2f}s, wanted "
                         f"{want:.2f}s -- truncated, cadence is short")
        self.say(f"# played ~{cfg['cycles']} cycles of {cfg['freq']} Hz "
                 f"{on * 10}/{off * 10} ms in {played:.2f}s")
        if ata:
            return self.handover("after second dial tone")
        # Hold SILENT off-hook in voice mode.  The polarity flip below hands
        # over, so the CX93001's S7 window is centered on the moment `g` clears.
        self.tone_done_at = time.time()
        self.say(f"# holding silent off-hook; polarity in "
                 f"{self.polarity_delay:.1f}s")

    def throw_polarity(self, why):
        self.thrown = True
        if self.polarity is not None:
            self.polarity.set(True)
        self.say(f"# LINE POLARITY REVERSED ({why})")
        if not self.handed_over:
            self.handover("on polarity reversal")

    def handover(self, why):
        """Voice -> data, still off-hook, and answer.  Order matters: the ATA
        must come after the card has gone off-hook and dialed."""
        self.handed_over = True
        self._at("AT+FCLASS=0")
        self.m.write(b"ATS0=0 S7=%d\r" % self.s7)
        self.m.flush()
        time.sleep(0.2)
        self.say(f"> ATA ({why})")
        self.m.write(b"ATA\r")
        self.m.flush()

    def _keys(self):
        while not self.stop_flag:
            try:
                line = sys.stdin.readline()
            except Exception:                                    # noqa: BLE001
                return
            if not line:
                return
            c = line.strip().lower()[:1]
            if c == "q":
                self.stop_flag = True
                return
            self.manual = {"t": "tone", "p": "polarity", "n": "normal",
                           "h": "hangup"}.get(c, "sdt")

    def _rearm(self, why):
        """End of one attempt, not of the tool.

        CPU2 needs a power cycle between calls anyway, so the useful thing
        after NO CARRIER is to be ready for the next ENTER rather than to
        exit -- the operator power-cycles the FCNS and goes again.  The
        framer is reset too, so a half-frame from a dropped call cannot
        merge into the next one.
        """
        self.say(f"# attempt over ({why}) -- ENTER to run another, q to stop")
        self.connected_at = self.tone_done_at = self.no_carrier_at = None
        self.thrown = self.handed_over = self.com_sent = False
        self.sess.framer = Framer(self.sess.log)
        if self.polarity is not None:
            self.polarity.set(False)
            self.say("# polarity back to normal, ready for the next off-hook")

    def run(self) -> int:
        self.m.write(b"ATS0=0 S7=%d\r" % self.s7)
        self.m.flush()
        time.sleep(0.5)
        self.m.reset_input_buffer()
        self.say(f"init> ATS0=0 S7={self.s7} (auto-answer OFF; ATA is manual)")
        self.say("keys: ENTER = second dial tone (then auto-polarity) · "
                 "t = tone only · p = polarity now · n = normal · "
                 "h = hang up · q = stop")
        threading.Thread(target=self._keys, daemon=True).start()

        buf, last_rx = b"", 0.0
        # No deadline.  A timer here only ever killed a live session; the
        # operator decides when the bench is done.
        while not self.stop_flag:
            chunk = self.m.read(256)
            if chunk:
                if self.rawlog:
                    self.rawlog.write(chunk)
                    self.rawlog.flush()
                if self.connected_at:
                    self.say(f"<< {len(chunk)}B {chunk.hex(' ')}")
                    # Only feed the session once the link is up; before that
                    # the port carries the modem's own result codes.
                    for n, reply in enumerate(self.sess.feed(chunk)):
                        if n and BLOCK_GAP:
                            time.sleep(BLOCK_GAP)
                        self.m.write(reply)
                        self.m.flush()
                        self.say(f"** SENT {len(reply)}B")
                buf += chunk
                last_rx = time.time()
                *lines, buf = buf.split(b"\r\n")
                for raw in lines:
                    s = raw.decode("ascii", "replace").strip()
                    if not s:
                        continue
                    # Once the link is up this view is a liability: a card frame
                    # ends in a bare CR, so it sits in `buf` until some later
                    # CRLF -- NO CARRIER's, usually -- splits it out and prints
                    # it again, minutes after the `<<` hex line that already
                    # recorded it byte-exactly.  That reads exactly like the
                    # card retransmitting.  Keep only the modem's own words.
                    if (not self.connected_at
                            or any(k in s for k in ("CONNECT", "NO CARRIER",
                                                    "ERROR", "BUSY", "RING"))):
                        self.say(f"< {s}")
                    if "CONNECT" in s and self.connected_at is None:
                        self.connected_at = time.time()
                        self.say("# CONNECT -- data mode")
                    if "NO CARRIER" in s:
                        self.no_carrier_at = time.time()
            elif buf and last_rx and time.time() - last_rx > 1.0:
                # Card frames end in a bare CR, so they never split here and
                # would be dumped a second time a second later -- which reads
                # exactly like the card retransmitting.  The `<<` hex above is
                # already byte-exact, so drop the duplicate once the link is up.
                if not self.connected_at:
                    self.say(f"< [no CRLF, {len(buf)}B] {buf.hex(' ')}")
                buf = b""

            if (self.tone_done_at and not self.thrown
                    and time.time() - self.tone_done_at >= self.polarity_delay):
                self.throw_polarity(f"auto, {self.polarity_delay:.1f}s "
                                    "after the tone")

            if (self.connected_at and not self.com_sent
                    and time.time() - self.connected_at >= self.com_delay):
                self.com_sent = True
                # CPU2 sub-state 3 ($EED0) slides a search for "COM" through
                # its buffer from $0505, so the FIRST byte received ($0504) is
                # outside the window -- the CRLF preamble is load-bearing.
                self.m.write(b"\r\nCOM\r\n")
                self.m.flush()
                self.say(">> \\r\\nCOM\\r\\n")

            if self.no_carrier_at and time.time() - self.no_carrier_at > 3.0:
                self._rearm("NO CARRIER")

            if self.manual:
                what, self.manual = self.manual, None
                if what == "tone":
                    self.sdt_sequence("manual, tone only", ata=False)
                    self.tone_done_at = None          # no auto-polarity
                elif what == "polarity":
                    self.throw_polarity("manual")
                elif what == "normal":
                    if self.polarity is not None:
                        self.polarity.set(False)
                    self.thrown = False
                    self.say("# LINE POLARITY BACK TO NORMAL")
                elif what == "hangup":
                    self._at("ATH")
                else:
                    self.sdt_sequence("manual")

        self.say("# done")
        n = len(self.sess.seen)
        self.log(f"-- {n} frame(s) from the card")
        return 0 if n else 1


def call(port, polarity_port, out, s7, polarity_delay, sdt) -> int:
    from polarity import Polarity

    sink = open(out, "w") if out else None

    def log(m):
        print(m, flush=True)
        if sink:
            sink.write(m + "\n")
            sink.flush()

    log(f"modem   : {ports.describe(port)}")
    pol = Polarity(polarity_port) if polarity_port else None
    if pol is not None and pol.live:
        # `?` before every run: the board is PC-powered, so `reversed` survives
        # the power cycles that would otherwise clear it.
        log(f"polarity: {ports.describe(polarity_port)}")
        log(f"polarity: {pol._cmd('?')}")
        pol.set(False)
    else:
        log("polarity: no relay port -- throw the switch by hand on `p`")

    raw = open(os.path.splitext(out)[0] + ".bin", "wb") if out else None
    c = Call(port, None, log, pol, sdt, s7, polarity_delay, rawlog=raw)
    # Session lines go through Call.say so they carry the same timestamps as
    # the modem traffic -- correlating a frame with a CONNECT after the fact is
    # the whole point of the log.
    c.sess = Session(c.say)
    # Load and check the page BEFORE any dialing: a bad page file should cost
    # a log line here, not a call.  After this it is re-read per request, so
    # editing page.py mid-session is the intended way to work.
    PAGES.poll(force=True)
    if PAGES.mod is None:
        log("!! no serveable page -- fix the page file and start again")
        return 1
    try:
        return c.run()
    except KeyboardInterrupt:
        log("interrupted")
        return 0
    finally:
        if pol is not None and pol.live:
            pol.set(False)
            log("polarity: restored to normal")
        if raw:
            raw.close()
        if sink:
            sink.close()


def serve(port: str, com: bool, seconds: float, out: str) -> int:
    import serial
    sink = open(out, "w") if out else sys.stdout
    t0 = time.time()

    def log(m):
        sink.write(f"[{time.time() - t0:8.3f}] {m}\n")
        sink.flush()
        if sink is not sys.stdout:
            print(m)

    sess = Session(log)
    PAGES.poll(force=True)
    if PAGES.mod is None:
        log("!! no serveable page -- fix the page file and start again")
        return 1
    m = serial.Serial(port, 115200, timeout=0.2)
    raw = open(os.path.splitext(out)[0] + ".bin", "wb") if out else None
    log(f"serving on {ports.describe(port)}")
    if com:
        # CPU2 sub-state 3 ($EED0) slides a search for "COM" through its
        # receive buffer starting at $0505, so the first byte received ($0504)
        # is outside the window -- the preamble is load-bearing.
        m.write(b"\r\nCOM\r\n")
        m.flush()
        log(">> \\r\\nCOM\\r\\n")
    while time.time() - t0 < seconds:
        chunk = m.read(256)
        if not chunk:
            continue
        if raw:
            raw.write(chunk)
            raw.flush()
        log(f"<< {len(chunk)}B {chunk.hex(' ')}")
        for n, reply in enumerate(sess.feed(chunk)):
            if n and BLOCK_GAP:
                time.sleep(BLOCK_GAP)
            m.write(reply)
            m.flush()
    log("done")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="run every ROM-backed check over the page file and "
                         "print the report. No hardware, no capture -- this is "
                         "the one to run in a second terminal while editing.")
    ap.add_argument("--page", metavar="FILE", default=DEFAULT_PAGE,
                    help="what to serve (default: site_page.py, the whole "
                         "service). Re-read before every reply, so editing it "
                         "mid-call is expected. --probe-page is the shorthand "
                         "for the page.py experiment dial.")
    ap.add_argument("--probe-page", dest="page", action="store_const",
                    const=PROBE_PAGE,
                    help="serve page.py, the single-page experiment dial "
                         "(its EXPERIMENT = picks which one)")
    ap.add_argument("--replay", help="feed a captured .farend.bin through it")
    ap.add_argument("--call", metavar="PORT", nargs="?", const=AUTO,
                    help="run the whole call: manual ATA, automatic polarity, "
                         "COM, then answer the card. The modem is discovered "
                         "by USB identity when no PORT is given "
                         "(tools/ports.py); $MODEM pins it.")
    ap.add_argument("--serve", metavar="PORT", nargs="?", const=AUTO,
                    help="answer on an ALREADY-connected far end. Same "
                         "discovery as --call.")
    ap.add_argument("--com", action="store_true",
                    help="--serve only: send the \\r\\nCOM\\r\\n preamble on start")
    ap.add_argument("--polarity-port", default=None,
                    help="relay CDC port (Line Polarity Relay). Discovered by "
                         "USB identity if omitted (tools/ports.py); $POLARITY "
                         "pins it, --no-polarity leaves the relays alone and "
                         "logs a flip you throw by hand.")
    ap.add_argument("--no-polarity", dest="use_polarity", action="store_false",
                    default=True,
                    help="do not drive the relays even if the board is present")
    ap.add_argument("--polarity-delay", type=float, default=1.0,
                    help="seconds after the tone stops before the relays throw")
    ap.add_argument("--s7", type=int, default=30,
                    help="seconds ATA waits for a carrier")
    ap.add_argument("--sdt-freq", type=int, default=SDT_DEFAULTS["freq"])
    ap.add_argument("--sdt-on", type=int, default=SDT_DEFAULTS["on"],
                    help="tone, in +VTS units of 10 ms (must be SHORTER than "
                         "the gap)")
    ap.add_argument("--sdt-off", type=int, default=SDT_DEFAULTS["off"])
    ap.add_argument("--sdt-cycles", type=int, default=SDT_DEFAULTS["cycles"])
    ap.add_argument("--reject", action="store_true",
                    help='answer "0004" with "0006" (wrong PIN, draw a message '
                         "and return to the prompt) instead of the \"0005\" "
                         "accept. The fully-understood path -- use it to prove "
                         "the round trip without relying on the undecoded "
                         '"0005" record fields.')
    ap.add_argument("--seconds", type=float, default=120.0,
                    help="--serve only; --call runs until you press q")
    ap.add_argument("--out", default="", help="log file (default: stdout only)")
    a = ap.parse_args()

    global REJECT_PIN
    REJECT_PIN = a.reject
    PAGES.path = a.page

    if a.check:
        PAGES.log = print
        return 0 if PAGES.poll(force=True) else 1
    if a.selftest:
        return selftest()
    if a.replay:
        replay(a.replay)
        return 0
    if a.call or a.serve:
        # /dev/ttyACM numbers are enumeration order and they move; a run
        # pointed at the wrong one goes quiet rather than failing.
        given = a.call or a.serve
        port = ports.find("modem", None if given is AUTO else given)
        console = ports.find("console", None, required=False)
        if ports.same_device(port, console):
            sys.exit(f"server: the far-end port resolves to the cart console "
                     f"({os.path.realpath(port)}).\n"
                     "  The card's frames would go to the console and the "
                     "replies nowhere.\n  `python3 tools/ports.py` lists what "
                     "is plugged in and what each port is.")
        pol = (ports.find("polarity", a.polarity_port, required=False)
               if a.use_polarity else None)
        if a.call:
            sdt = {"freq": a.sdt_freq, "on": a.sdt_on,
                   "off": a.sdt_off, "cycles": a.sdt_cycles}
            return call(port, pol, a.out, a.s7, a.polarity_delay, sdt)
        return serve(port, a.com, a.seconds, a.out)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
