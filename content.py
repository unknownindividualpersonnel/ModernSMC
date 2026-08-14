#!/usr/bin/env python3
"""SMC content records -- the payload of a "0005" reply.

The card's `"0005"` (PIN accepted) reply carries a *content record*, which
bank 6 `$AC67` parses into the six build buffers the menu screen draws from.
That parser is ~700 bytes long and raises thirteen distinct errors, `4940`
through `494C`.  This module builds records and blocks, and checks them the way
the card would -- `cardmodel.py` holds the rules, so no ROM image is needed.

Given one (`$SMC_ROM`, or `roms/smc.nes`), `Card` runs the card's actual code
in a 6502 emulator instead, and `--selftest` cross-checks the two.

    python3 content.py --selftest     # the rules, and the ROM if there is one
    python3 content.py --demo         # build + verify + dump buffers
    python3 content.py --names        # the built-in name table (needs a ROM)

The grammar, from `$AC67`-`$AFC0` and verified by executing it:

    <field1> '/' <field2> '/' <field3> '/' <field4> '/' <$03|$04>

**Four separators, not three** -- field 4 carries its own trailing `'/'` even
when it is empty.  A record whose field 4 is empty is `... / / / / $03`.

field 1 -- the menu structure, 1..16 entries.  Each entry is

    <name> <action> ( <sel> <param> ){1,8} '*'

and the *last* entry ends with `'/'` instead of `'*'` (a trailing `"*/"` is
error `4940`, because the parser then tries to read `'/'` as the next name).

  * `<name>`  `$80` = take the next 16 bytes of field 2 (an inline name);
              `$81`..`$FF` = index `(code & $7F) - 1` into the ROM name table
              at **bank 1 `$8000`**, 16 bytes per entry (`$F490`).
              Anything `< $80` is `4940`.
  * `<action>` `$80` = this entry owns the next content page in field 4 (the
              stored value is the page ordinal, `$051E`); `$7F` or `> $80` is
              stored as-is.  Anything else is `4941`.
  * `<sel>`   `$80` = consume the next 25 bytes of field 3 (the stored value
              is the record ordinal `$051F`, max 55 -> `494C`);
              `> $80` stored as-is; `< $80` is `4942`.
  * `<param>` must be `>= $7F`, else `4943`.
  * 9 items in one entry -> `494B`; 0 items -> `4945`; 17 entries -> `494A`.

field 2 -- the inline names, 16 bytes each, one per `$80` name code.  The
          cursor must land exactly on the `'/'`, else `4946`.
field 3 -- 25-byte records, one per `$80` item selector.  Else `4947`.
field 4 -- one token-stream page per `$80` action byte, pages separated by
          `'*'`, the last ended by `'/'`.  Any other byte is `4948`; a page
          whose tokens run past the record terminator is `4949`; a page that
          would push the build buffer past `$8000` is `494C`.

A field-4 page is a stream of tokens (`$F7A8`/`$F7E3`), each of which is

    $80 <6 bytes> <n>  <n-1 bytes>      advance 7 + (byte[7] & $7F)
    $C1 <8 bytes> <n>  <n-1 bytes>      advance 9 + (byte[9] & $1F)
    '(' <b1 & $70 == $20> ... ')'       a group; tokens nest inside

Anything else -- including a `$9x`/`$Ax`/`$Bx`/`$Dx`/`$Ex`/`$Fx` lead byte --
is `4948`.  Only the lead byte of each token is validated; the parser copies
the page verbatim into the `$7AA0` buffer and the drawing code interprets it.

**No `$03` or `$04` may appear anywhere in the record except as the final
terminator.**  `$ACDD` finds the terminator by scanning field 4 for the first
`$03`/`$04`, so an embedded one -- a token *length byte* of `$04`, say --
silently truncates the record and shows up much later as `4949`.  `$03` is
already ruled out one layer down (CPU2 ends the block at the first `$03`);
`$04` is not, and it is the one that bites.

The parser fills, in W-RAM:

    $7800+i        entry i action byte  (or its page ordinal)
    $7810+i        entry i item count
    $7820+i*16     entry i item bytes   (2 per item: sel, param)
    $7920+i*22     entry i display line (6 spaces + the 16-byte name)
    $7A80+p*2      pointer to page p in the $7AA0 buffer
    $7AA0...       the field-4 pages, each `$03`-terminated

16*22 = 352 = $160, so `$7920 + $160` is exactly `$7A80`: the 16-entry cap is
structural, not arbitrary.

Three `4949` sites (`$ACAB`, `$AECA`, `$AFA7`) are **dead code** -- they are
guarded by `CMP #$03 / BNE x / CMP #$04 / BNE x`, and A cannot be both.  Only
`$AF8E` can raise `4949`.
"""

import argparse
import os
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tools"))
from cardmodel import CardModel  # noqa: E402


def rom_path():
    """A ROM image to cross-check against, or None.  Nothing here needs one."""
    env = os.environ.get("SMC_ROM")
    if env:
        return env if os.path.exists(env) else None
    local = os.path.join(HERE, "roms", "smc.nes")
    return local if os.path.exists(local) else None


def checker(rom=None):
    """The validator to run a page through: the card itself, or the model."""
    rom = rom or rom_path()
    return Card(rom) if rom else CardModel()


ROM = rom_path()

RECORD_ADDR = 0x610A        # where $A800 points $78/$79 before calling $AC67
PARSE = 0xAC67
MEASURE = 0x80B7            # bank 5, pass 5: build the field table
MEASURE_DONE = 0x8138       # $810C stores the $FF, $8138 jumps back to $802F
FIELD_TABLE = 0x71D7        # $80D2/$96CE/$90F2 all point $B2/$B3 here
FIELD_TABLE_TOP = 0x7800    # $AC67's build buffer -- nothing bounds the table
                            # below it, and a field costs 6 to 9 bytes
F1_MARKER = 0xF1            # $85E2's current-field record; $9732 consumes it
TRAILER_VALIDATE = 0x87AF   # bank 5, reached from $BC90 via $FE76
ERROR_SINK = 0xE5F8         # $AFF0 jumps here with the low byte in A
SENTINEL = 0x6FFD           # cpu6502.run_subroutine's return marker

NAME_TABLE_BANK = 1         # $F490: LDA #$01 / JSR $CE4D, then $8000 + (n-1)*16
NAME_TABLE_ADDR = 0x8000
NAME_LEN = 16

# The card's own PAGE DIRECTORY, also bank 1: 34 entries of 25 bytes, each
# `<NNN><22-byte title>`, codes 001..034, with a second block after a gap
# (041, 043..050).  These are the SUB-MENU lines of the record page -- the
# list the manual (p.14 step 9) calls サブメニュー, chosen with Up/Down under a
# main-menu box chosen with Left/Right.
#
# The base is bank 7 `$F571`'s own: `$87F0 + 25 * (code - $81)`.  The five
# spaces that sit in front of `001` belong to whatever precedes the table, not
# to the record -- reading from `$87EB` costs the last five bytes of every
# title, which is why 009 and 031 used to come out cut mid-character.
#
# The directory is not all Super Mario Club: 001-010 and most of 013-034 are a
# securities service (株式時価, 転換社債, ＣＢ時価...), and SMC's own live at
# 011 推奨ソフト速報, 012 推奨ソフト情報, 021 ソフト会員から, 022 流通会員から,
# 023 事務局から -- 流通会員 and ソフト会員 being the two membership types the
# manual names.  The platform was shared; the card ships every code either
# service might send.
PAGE_DIR_ADDR = 0x87F0      # $F571: ADC #$F0 / ADC #$87
PAGE_DIR_LEN = 25
PAGE_CODE_LEN = 3           # $F3C6 sends $0501-$0503 as the request's section
PAGE_DIR_COUNT = 34
FIELD3_LEN = 25             # $AE37: LDA #$19 / STA $7A
MAX_ENTRIES = 16
MAX_ITEMS = 8
MAX_FIELD3 = 55             # $AE25: CMP #$37 -> the 56th field-3 item is 494C

SLASH, STAR, ETX, EOT = 0x2F, 0x2A, 0x03, 0x04

# The rest of the page loop: pass 6 rebuilds the cursor map for the pane $B8
# names, $9BC7 is Up/Down, and $98A8 serializes the form EXECUTE sends.
PASS6 = 0x96B6
CURSOR_KEY = 0x9BC7
SUBMIT = 0x98A8
SUBMIT_OUT, SUBMIT_LEN = 0x600A, 0x6E49
KEY_UP, KEY_DOWN, KEY_EXECUTE, KEY_INDEX = 0x51, 0x52, 0x42, 0x45

NORMALIZE = 0xFAE1          # bank 7: scatter a token header into $718F
CANON = 0x718F              # the 14-slot canonical header $FAE1 builds
CANON_SLOTS = 14            # $FAE1: LDY #$0D, counting down
CANON_MAPS = 0xFA91         # five pointers, indexed by the $FBBE type
CANON_TYPES = (0xC0, 0x80, 0xA0, 0xC1, 0x81)    # types 0-4, the mapped ones
SCRATCH = 0x6400            # a free W-RAM page to stage a token in


# ---------------------------------------------------------------- the machine

class Card:
    """Enough of the card to run `$AC67`: RAM, W-RAM, and MMC1 banking.

    Optional: it needs a ROM image, which is not distributed.  Use checker().
    """

    modeled = True

    def __init__(self, path=None):
        from cpu6502 import CPU
        path = path or rom_path()
        if not path:
            raise FileNotFoundError(
                "no SMC ROM image: set $SMC_ROM to a dump of your own "
                "cartridge, or drop it at roms/smc.nes.  Nothing in the "
                "server needs one -- content.checker() falls back to "
                "cardmodel.CardModel, which needs no ROM.")
        with open(path, "rb") as fh:
            img = fh.read()
        self.prg = img[16:]
        self.nbanks = len(self.prg) // 0x4000
        self.ram = bytearray(0x800)
        self.wram = bytearray(0x2000)
        self.bank = 6                      # the content layer lives in bank 6
        self.shift = 0
        self.count = 0
        self.cpu = CPU(self.read, self.write)

    # ---- memory map -------------------------------------------------------
    def read(self, a):
        a &= 0xFFFF
        if a < 0x2000:
            return self.ram[a & 0x7FF]
        if 0x6000 <= a < 0x8000:
            return self.wram[a - 0x6000]
        if 0x8000 <= a < 0xC000:
            return self.prg[self.bank * 0x4000 + (a - 0x8000)]
        if a >= 0xC000:
            return self.prg[(self.nbanks - 1) * 0x4000 + (a - 0xC000)]
        return 0

    def write(self, a, v):
        a &= 0xFFFF
        v &= 0xFF
        if a < 0x2000:
            self.ram[a & 0x7FF] = v
        elif 0x6000 <= a < 0x8000:
            self.wram[a - 0x6000] = v
        elif a >= 0x8000:
            self._mmc1(a, v)

    def _mmc1(self, a, v):
        """Serial MMC1 register.  `$CE6F` writes five bits to `$EAFF`, which
        is `$E000-$FFFF` -> register 3, the PRG bank."""
        if v & 0x80:
            self.shift = self.count = 0
            return
        self.shift |= (v & 1) << self.count
        self.count += 1
        if self.count == 5:
            if (a >> 13) & 3 == 3:
                self.bank = self.shift & 0x0F
            self.shift = self.count = 0

    # ---- the parser -------------------------------------------------------
    def parse(self, record, addr=RECORD_ADDR, max_steps=5_000_000):
        """Run `$AC67` over `record`.  Returns a dict with `error` (a
        four-digit string, or None) and, on success, the built buffers."""
        # The parser writes its output over $7800-$7AFF but never clears it,
        # so without this a short record inherits the previous one's page
        # pointers at $7A80 and buffers() reports pages that are not there.
        for a in range(0x7800, 0x8000):
            self.wram[a - 0x6000] = 0
        for i, b in enumerate(record):
            self.write(addr + i, b)
        self.write(0x78, addr & 0xFF)
        self.write(0x79, addr >> 8)
        self.write(0x8B, 6)            # $F490 restores the bank from here
        self.write(0x58, 6)            # ...and $CE4D's shadow of it

        cpu = self.cpu
        cpu.a = cpu.x = cpu.y = 0
        cpu.sp = 0xFD
        cpu.C = cpu.Z = cpu.I = cpu.D = cpu.B = cpu.V = cpu.N = 0
        ret = (SENTINEL - 1) & 0xFFFF
        cpu.push((ret >> 8) & 0xFF)
        cpu.push(ret & 0xFF)
        cpu.pc = PARSE

        for _ in range(max_steps):
            if cpu.pc == SENTINEL:
                return {"error": None, "entries": cpu.a, "buffers": self.buffers()}
            if cpu.pc in (0xE5F0, ERROR_SINK, 0xE600):
                return {"error": "49%02X" % cpu.a, "entries": None, "buffers": None}
            cpu.step()
        raise RuntimeError("parser ran away (pc=$%04X)" % cpu.pc)

    def buffers(self):
        w = self.wram
        def g(lo, hi):
            return bytes(w[lo - 0x6000:hi - 0x6000])
        pages = []
        table = g(0x7A80, 0x7AA0)
        for p in range(0, 32, 2):
            ptr = table[p] | table[p + 1] << 8
            if ptr == 0:
                continue
            end = ptr
            while end < 0x8000 and w[end - 0x6000] != ETX:
                end += 1
            pages.append(g(ptr, end))
        return {
            "action": g(0x7800, 0x7810),
            "counts": g(0x7810, 0x7820),
            "items": g(0x7820, 0x7920),
            "lines": g(0x7920, 0x7A80),
            "pages": pages,
        }

    # ---- the trailer, validated by bank 5 --------------------------------
    def check_trailer(self, block, max_steps=100_000):
        """Run bank 5's `$87AF` over `block`.

        The record is NOT the end of a `"0005"` reply.  `$FE76` sees the `$04`
        terminator, switches to **bank 5** and jumps `$BC90`; `$BD45` captures
        the terminator pointer `$B8/$B9` into `$D8/$D9`, `$BCAD` steps it one
        past the terminator, copies `(byte[1] & $0F) + 2` bytes from there to
        `$610A`, and `$87AF` validates them.  So the bytes immediately after
        the record terminator are a header block of their own:

            <b0> <b1> <n bytes>        n = b1 & $0F

        `b0`: high nibble `$8`/`$9`/`$A`, else **`4970`**; `$Ax` is accepted
              outright, `$8x`/`$9x` additionally need a low nibble `< 4`.
        `b1`: high nibble `$8`/`$9`/`$A`, else **`4971`**; `$8x` is accepted
              outright.  For `$9x`/`$Ax`, `n = b1 & $0F` must be `< 10` (else
              `4971`) and the `n` bytes after `b1` must each be `$80`-`$89`
              (else **`4972`**).

        Measured 2026-08-08: with `'0'` padding sitting after the terminator,
        `b0 = $30` and the card shows **`4970`** -- which means the record
        itself was accepted by all thirteen of `$AC67`'s validators.
        """
        for i, b in enumerate(block):
            self.write(RECORD_ADDR + i, b)
        cpu = self.cpu
        cpu.a = cpu.x = cpu.y = 0
        cpu.sp = 0xFD
        cpu.C = cpu.Z = cpu.I = cpu.D = cpu.B = cpu.V = cpu.N = 0
        ret = (SENTINEL - 1) & 0xFFFF
        cpu.push((ret >> 8) & 0xFF)
        cpu.push(ret & 0xFF)
        cpu.pc = TRAILER_VALIDATE
        self.bank = 5
        try:
            for _ in range(max_steps):
                if cpu.pc == SENTINEL:
                    return None
                if cpu.pc in (0xE5F0, ERROR_SINK, 0xE600):
                    return "49%02X" % cpu.a
                cpu.step()
        finally:
            self.bank = 6
        raise RuntimeError("$87AF ran away (pc=$%04X)" % cpu.pc)

    def check_content(self, block):
        """The whole thing after the record terminator: header, then stream.

        `$BCAD` reads `count = (byte[1] & $0F) + 2`, copies that many bytes to
        `$610A` for `$87AF` to validate, and -- the instruction that is easy to
        miss -- `$BCCD: JSR $8B92` **adds the same count to `$B0`**.  So the
        token stream `$BCE4` walks starts *after* the header, not at it.
        `$80B7` repeats the arithmetic on the relocated copy at `$610A`.

            <b0> <b1> <count-2 bytes>     header, validated by $87AF
            <token> <token> ...           stream, walked until $03

        Returns `{"error", "header", "stream", "walk"}`.
        """
        out = {"error": None, "header": b"", "stream": b"", "walk": None}
        if len(block) < 2:
            out["error"] = "4970"
            return out
        bad = self.check_trailer(block)
        if bad is not None:
            out["error"] = bad
            return out
        n = (block[1] & 0x0F) + 2
        out["header"], out["stream"] = block[:n], block[n:]
        if len(block) < n:
            out["error"] = "4970"
            return out
        walk = self.walk_stream(out["stream"])
        out["walk"] = walk
        if walk["error"]:
            out["error"] = walk["error"]
        elif not walk["clean"]:
            out["error"] = "stream does not land on the card's $03"
        return out

    def walk_stream(self, block, addr=0x6200, max_steps=300_000):
        """Follow bank 5's `$88D0` token by token through `block`.

        `$BCE4` walks the content stream from the trailer onwards and stops
        only when it reads `$03`.  **The card supplies that `$03` itself**:
        `$EF32` appends each block's data at the running pointer `$6E29/$6E2A`
        and bank 6 `$8812` then calls `$F3F8`, which stores `$03` at exactly
        that pointer -- one byte past the last byte we sent.

        So the stream terminates iff the tokens land exactly on the end of the
        data.  Trailing `'0'` padding does not terminate it; it is read as a
        token lead byte and `$881D` raises `4980`.  Measured on hardware
        (`serve6`, 2026-08-08).

        Returns `{"tokens": [(offset, lead, length)], "ends_at": n,
        "clean": bool, "error": code}`.  `length` is None for lead bytes whose
        handler needs machine state this harness does not model.
        """
        out = {"tokens": [], "ends_at": None, "clean": False, "error": None}
        for i in range(len(block) + 64):
            self.write(addr + i, ETX if i >= len(block) else block[i])
        off = 0
        while off < len(block):
            lead = block[off]
            bad = self.check_token(lead)
            if bad is not None:
                out["error"] = bad
                out["ends_at"] = off
                return out
            nxt = self._advance(addr + off, max_steps)
            if nxt is None:
                out["tokens"].append((off, lead, None))
                out["ends_at"] = None
                return out
            if isinstance(nxt, str):
                out["error"] = nxt
                out["ends_at"] = off
                return out
            out["tokens"].append((off, lead, nxt))
            off += nxt
        out["ends_at"] = off
        out["clean"] = off == len(block)
        return out

    def check_token(self, lead):
        """Run `$881D` over one lead byte: `4980` below `$80`, `4988` above."""
        return self._run(0x881D, a=lead, setup={0xBD: 0})

    # ---- the canonical header ---------------------------------------------
    def header(self, token, addr=SCRATCH):
        """Run `$FAE1` over one token; return its 14 canonical header slots.

        Every renderer starts here, so this is the ground truth for what a
        token header *means*: `$FAE1` scatters the type's own bytes into fixed
        slots at `$718F` and leaves the slots that type does not have at zero.
        """
        for i, b in enumerate(token):
            self.write(addr + i, b)
        self._run(NORMALIZE, setup={0x60: addr & 0xFF, 0x61: addr >> 8})
        return self.read_range(CANON, CANON_SLOTS)

    def header_map(self, lead):
        """`$FAE1`'s scatter map for one lead byte, read out of the ROM.

        Entry `i` is the token offset that lands in slot `i`, or None when the
        type has no byte for that slot.  The highest entry is therefore the
        type's **header length minus one**.
        """
        base = (self.nbanks - 1) * 0x4000
        kind = self._run(0xFBBE, a=lead)
        if isinstance(kind, str):
            return None
        kind = self.cpu.a
        if kind >= len(CANON_TYPES):
            return None
        p = CANON_MAPS - 0xC000 + kind * 2
        at = self.prg[base + p] | self.prg[base + p + 1] << 8
        raw = self.prg[base + at - 0xC000: base + at - 0xC000 + CANON_SLOTS]
        return [None if b == 0xFF else b for b in raw]

    def _advance(self, at, max_steps):
        """`$88D0`: how many bytes this token occupies, or None if its handler
        needs state this harness does not model."""
        r = self._run(0x88D0, setup={0xB0: at & 0xFF, 0xB1: at >> 8, 0xBD: 0},
                      max_steps=max_steps)
        if isinstance(r, str):
            return None if r.startswith("RUNAWAY") else r
        return (self.read(0xB1) << 8 | self.read(0xB0)) - at

    def _run(self, addr, a=0, setup=None, max_steps=300_000, until=None):
        cpu = self.cpu
        for k, v in (setup or {}).items():
            self.write(k, v)
        cpu.x = cpu.y = 0
        cpu.sp = 0xFD
        cpu.C = cpu.Z = cpu.I = cpu.D = cpu.B = cpu.V = cpu.N = 0
        cpu.a = a
        ret = (SENTINEL - 1) & 0xFFFF
        cpu.push((ret >> 8) & 0xFF)
        cpu.push(ret & 0xFF)
        cpu.pc = addr
        was, self.bank = self.bank, 5
        try:
            for _ in range(max_steps):
                if cpu.pc == SENTINEL or cpu.pc == until:
                    return None
                if cpu.pc in (0xE5F0, ERROR_SINK, 0xE600):
                    return "49%02X" % cpu.a
                cpu.step()
            return "RUNAWAY $%04X" % cpu.pc
        finally:
            self.bank = was

    # ---- the measure pass, and the field table it builds ------------------
    def measure(self, block, max_steps=2_000_000):
        """Run bank 5's `$80B7` over a content block and report `$71D7`.

        `$80B7` is pass 5 (`$BE = 5`): it walks the stream with `$81E0` and
        **registers a field** for every bracket it meets, building a table of
        variable-length descriptors at `$71D7` that pass 6 (`$96B6`, `$8BC2`)
        and pass 7 (`$90DF`, `$9AC3`) then drive.

        The table ends at `$FF`, and the interesting record is `$F1` -- written
        by `$85E2`, which `$8317` calls **only when `$BD == 1`**, i.e. only
        when one of a flavor-0 group's alternatives holds a nested bracket
        after its first token (`$82F6`, `$830A`).  `$96B6` turns that record
        into `$B8`/`$B9`/`$BA`, the current-field context.

        **`interactive` does NOT mean "responds to the D-pad".**  It was read
        that way from `serve13` and that reading is WRONG, measured
        2026-08-09: a group with no `$F1` record at all still cycles on Left /
        Right (`$9C28`).  serve13 drew its three alternatives at one column and
        row, so the selection moved with nothing on screen to show it.  Draw
        them on separate rows and the cursor visibly walks between them.

        The reason is in this function's own output: **`$B9` is non-zero when
        pass 5 ends** -- so `$9B00`'s "`$B9` must be set" gate is already
        satisfied and `$9732` was never on the critical path.  What the `$F1`
        record does is re-point `$B9`/`$BA` at a **sub-field**, i.e. descend
        the cursor into a nested bracket inside an alternative.  That is a
        second level of widget, not the switch that turns the first one on.

        `$B9` is an **index into `$71BA`, the cursor map, and `$71BA` is keyed
        by SCREEN ROW** -- descriptor byte[1] is the row the field's first
        alternative is drawn on.  Up (`$51`) and Down (`$52`) walk that table
        for the next populated row (`$9BC7`), which is how a page moves between
        widgets.  Two fields on the SAME row share one slot: the second is
        drawn but unreachable, and Up/Down do nothing.  Confirmed on hardware
        both ways round.

        So when a page has several widgets, check byte[1] of each descriptor
        here -- if two match, the page has fewer working fields than it looks.

        Returns `{"error", "fields", "interactive", "b8", "c3", ...}`, plus
        `table_end`, where the `$FF` landed.  A long page's table grows over
        bank 2's own `$72xx` buffers, which is harmless: every one of them is
        seeded on entry to the record page (`$ACC4`, `$ABD4`, `$A7B0`).
        """
        for a in range(0x7100, 0x7200):              # $85E2 stages the $F1
            self.wram[a - 0x6000] = 0                # record here; clear first
        for a in range(FIELD_TABLE, FIELD_TABLE_TOP):
            self.wram[a - 0x6000] = 0
        for i in range(len(block) + 64):
            self.write(RECORD_ADDR + i, ETX if i >= len(block) else block[i])
        err = self._run(MEASURE, max_steps=max_steps, until=MEASURE_DONE)
        out = {"error": err if isinstance(err, str) else None, "modeled": True,
               "fields": [], "interactive": False, "table_end": FIELD_TABLE,
               "b8": self.read(0xB8), "b9": self.read(0xB9),
               "ba": self.read(0xBA), "c3": self.read(0xC3)}
        if out["error"]:
            return out
        at = FIELD_TABLE
        while at < FIELD_TABLE_TOP:
            b0 = self.read(at)
            if b0 == 0xFF:
                break
            n = self._field_advance(at)
            if not n or n < 1:
                out["error"] = "the $71D7 walk stalled at $%04X" % at
                break
            out["fields"].append(self._field(at, self.read_range(at, n)))
            at += n
        else:
            out["error"] = "the $71D7 table reached $%04X unterminated" % at
        out["table_end"] = at
        out["interactive"] = any(f["kind"] == "cursor" for f in out["fields"])
        return out

    def submit(self, key=KEY_EXECUTE, max_steps=2_000_000):
        """`$98A8` -- the payload this key press puts on the wire.

        `$600A` holds it and `$6E49` its length, so this is the request the far
        end will have to route: `'M'` for 目次, else `'0'` and the whole form.
        """
        self.write(SUBMIT_LEN, 0)
        err = self._run(SUBMIT, setup={0x82: key}, max_steps=max_steps)
        if isinstance(err, str):
            return None
        return bytes(self.read(SUBMIT_OUT + i)
                     for i in range(self.read(SUBMIT_LEN)))

    def reachable(self, block, max_steps=2_000_000):
        """Every row the cursor reaches on `block`, and what each one submits.

        Pass 5 builds the table, `$96B6` rebuilds `$71BA` for the pane in `$B8`,
        `$9BC7` walks it on Down and `$98A8` serializes the form -- the whole
        loop between drawing a page and the request its EXECUTE sends.  Panes
        are turned the way `$8078` does it, by stepping `$B8` and redrawing.

        Returns `{"error", "panes", "rows": [(pane, row, payload)], "payloads"}`.
        """
        m = self.measure(block, max_steps=max_steps)
        out = {"error": m["error"], "modeled": True,
               "panes": 0, "rows": [], "payloads": []}
        if m["error"]:
            return out
        out["panes"] = m["c3"] & 0x7F
        for pane in range(1, out["panes"] + 1):
            self.write(0xB8, pane)
            if isinstance(self._run(PASS6, max_steps=max_steps), str):
                out["error"] = "pass 6 faulted on pane %d" % pane
                return out
            # $B9 still names the pane we came from until the first Down.
            self._run(CURSOR_KEY, setup={0x82: KEY_DOWN}, max_steps=max_steps)
            seen = set()
            while self.read(0xB9) not in seen:
                seen.add(self.read(0xB9))
                out["rows"].append((pane, self.read(0xB9) & 0x7F, self.submit(
                    max_steps=max_steps)))
                if isinstance(self._run(CURSOR_KEY, setup={0x82: KEY_DOWN},
                                        max_steps=max_steps), str):
                    out["error"] = "the cursor walk faulted on pane %d" % pane
                    return out
        out["payloads"] = [p for _, _, p in out["rows"]]
        return out

    def read_range(self, at, n):
        return bytes(self.read(at + i) for i in range(n))

    def _field(self, at, raw):
        f = {"at": at, "raw": raw, "kind": "field"}
        if raw[0] == F1_MARKER:
            # $85E2: $F1, then $B8, $B9, $BA -- the current-field context that
            # $9732 loads back in pass 6, then one byte per alternative.
            f.update(kind="cursor", id=raw[1], b9=raw[2], ba=raw[3])
            return f
        f.update(id=raw[0] & 0x7F, nested=bool(raw[0] & 0x80))
        if len(raw) > 3:
            f.update(type=raw[3] & 0x0F, skip=bool(raw[3] & 0x10))
        if len(raw) > 5:
            f["token"] = raw[4] << 8 | raw[5]        # high byte FIRST ($829A)
        if len(raw) > 7:
            f.update(count=raw[6], selected=raw[7])
        return f

    def _field_advance(self, at, max_steps=300_000):
        """`$8AEA` -- the card's own stride over one `$71D7` descriptor."""
        r = self._run(0x8AEA, setup={0xB2: at & 0xFF, 0xB3: at >> 8},
                      max_steps=max_steps)
        if isinstance(r, str):
            return None
        return (self.read(0xB3) << 8 | self.read(0xB2)) - at

    # ---- the built-in page directory -------------------------------------
    def page_titles(self, count=PAGE_DIR_COUNT):
        """The `<code, title>` directory at bank 1 `$87F0`.

        Returns [(b'001', '株式時価'), ...].  A record entry's item SELECTOR
        indexes this when it is `$81` or above, `$81` being entry 0: a record
        whose items are `$8B $8C $95` draws 推奨ソフト速報 / 推奨ソフト情報 /
        ソフト会員から as the record page's sub-menu.  A selector of `$80`
        takes the same 25-byte shape from field 3 instead -- submenu_record().
        """
        base = NAME_TABLE_BANK * 0x4000 + PAGE_DIR_ADDR - 0x8000
        out = []
        for i in range(count):
            row = self.prg[base + i * PAGE_DIR_LEN:
                           base + (i + 1) * PAGE_DIR_LEN]
            out.append((bytes(row[:PAGE_CODE_LEN]),
                        row[PAGE_CODE_LEN:]
                        .decode("shift_jis", "replace").strip()))
        return out

    # ---- the built-in name table -----------------------------------------
    def names(self, count=16):
        base = NAME_TABLE_BANK * 0x4000 + NAME_TABLE_ADDR - 0x8000
        return [self.prg[base + i * NAME_LEN: base + (i + 1) * NAME_LEN]
                for i in range(count)]


# ---------------------------------------------------------------- the builder

def submenu_record(code, title, encoding="shift_jis"):
    """One sub-menu line, for an item whose selector is `$80`.

    Bank 7 `$F507` is the resolver, and it treats both kinds of item the same
    way.  It reads the item byte at `$7820 + entry*16 + item*2` and then:

        b <  $80    src = $7AA0 + 25*b            -- THIS record, out of the
                                                     adapter's own W-RAM, with
                                                     no bank switch ($F549)
        b >= $81    src = $87F0 + 25*(b - $81)    -- the ROM directory, via a
                                                     switch to bank 1 ($F561)

    and `$F4DA` copies the 25 bytes it lands on to `$0501`.  So an inline
    record has the directory's own layout --

        <3 ASCII digits><22-byte title>

    -- and the three digits are exactly what `$F3C6` copies into the request's
    SECTION field when the line is chosen.  An inline line therefore carries
    both what it says and what it asks for, which is how a server names pages
    of its own instead of the 34 the card happens to ship.

    `title` is padded to 22 bytes.  The only byte a record may not contain is
    `'/'`, which ends the field early ($AC67 then raises `4948`); `$03`/`$04`
    are refused by check_record() one layer up.
    """
    if isinstance(code, str):
        code = code.encode("ascii")
    if len(code) != PAGE_CODE_LEN:
        raise ValueError("the page code is %d bytes ($0501-$0503, which "
                         "$F3C6 sends as the section)" % PAGE_CODE_LEN)
    body = title.encode(encoding) if isinstance(title, str) else bytes(title)
    room = PAGE_DIR_LEN - PAGE_CODE_LEN
    if len(body) > room:
        raise ValueError("title is %d bytes; %d fit after the code"
                         % (len(body), room))
    rec = code + body.ljust(room, b" ")
    if SLASH in rec:
        raise ValueError("'/' ends the field early -- $AEF6 then finds the "
                         "field-3 cursor short and $AC67 raises 4948")
    return rec


def build_record(entries, term=EOT):
    # `term` is a live choice, not decoration: $FE76 dereferences it, $04
    # selects bank 5 and the content stream, $03 goes to $FE89 and the record
    # page.  $03 cannot be SENT -- CPU2 ends the inbound block at the first one
    # -- so `term=None` is how to get it: send no terminator and the card's own
    # $03 lands exactly where the record needs it.  check_record() has the rest.
    """Assemble a content record from a list of entry dicts:

        {"name":   0x81            -- ROM name-table code, or
                   b"<16 bytes>"   -- an inline name (goes in field 2)
         "action": 0x7F            -- literal action byte, or
         "page":   b"<tokens>"     -- a field-4 content page (action becomes $80)
         "items":  [(sel, param)]  -- sel: int >= $81, or b"<25 bytes>" for
                                      a field-3 record; param: int >= $7F}
    """
    if not 1 <= len(entries) <= MAX_ENTRIES:
        raise ValueError("1..%d entries" % MAX_ENTRIES)
    f1, f2, f3, f4 = bytearray(), bytearray(), bytearray(), bytearray()

    for n, e in enumerate(entries):
        name = e["name"]
        if isinstance(name, (bytes, bytearray)):
            if len(name) != NAME_LEN:
                raise ValueError("inline name must be %d bytes" % NAME_LEN)
            f1.append(0x80)
            f2 += name
        else:
            if not 0x81 <= name <= 0xFF:
                raise ValueError("name code must be $81..$FF")
            f1.append(name)

        page = e.get("page")
        if page is not None:
            f1.append(0x80)
            f4 += page
            f4.append(STAR)
        else:
            action = e.get("action", 0x7F)
            if action != 0x7F and action < 0x80:
                raise ValueError("action must be $7F or >= $80")
            f1.append(action)

        items = e.get("items", [])
        if not 1 <= len(items) <= MAX_ITEMS:
            raise ValueError("entry %d: 1..%d items" % (n, MAX_ITEMS))
        for sel, param in items:
            if isinstance(sel, (bytes, bytearray)):
                if len(sel) != FIELD3_LEN:
                    raise ValueError("field-3 record must be %d bytes" % FIELD3_LEN)
                f1.append(0x80)
                f3 += sel
            else:
                if sel < 0x81:
                    raise ValueError("item selector must be $80 or >= $81")
                f1.append(sel)
            if param < 0x7F:
                raise ValueError("item parameter must be >= $7F")
            f1.append(param)
        f1.append(STAR)

    f1[-1] = SLASH                       # the last entry ends with '/', not '*'
    if f4:
        f4[-1] = SLASH                   # ...and so does the last content page
    else:
        f4.append(SLASH)
    rec = bytes(f1 + f2 + bytes([SLASH]) + f3 + bytes([SLASH]) + f4)
    if term is not None:
        rec += bytes([term])
    check_record(rec, term)
    return rec


def check_record(rec, term=EOT):
    """The record terminator is found by scanning for the first `$03`/`$04`
    (`$ACDD`), so an embedded one truncates the record.

    `term=None` is the UNTERMINATED form: nothing is appended, and the card's
    own `$03` -- which `$F3F8` writes one byte past the last byte of the block
    -- becomes the terminator.  That is the only way to get an `$03` in front
    of `$AC67`, because CPU2 cuts the block at any `$03` we send ourselves, and
    `$FE7A` makes the two terminators mean different things:

        $04   $6E80 = 1, JMP $BC90    the trailer and its content stream
        $03   $6E80 = 0, JSR $A847    the RECORD PAGE, straight away

    so an unterminated record is how a reply lands on the menu with no content
    page in front of it -- which is what the manual's p.14 step 9 shows, and it
    also means the first sub-menu selection already carries its own code.
    """
    body = rec if term is None else rec[:-1]
    for stray in (ETX, EOT):
        i = body.find(stray)
        if i >= 0:
            raise ValueError("stray $%02X at offset %d truncates the record"
                             % (stray, i))
    if term is not None and rec[-1] not in (ETX, EOT):
        raise ValueError("record must end with $03 or $04")
    return rec


# Token shapes: (offset of the length byte, mask).  The advance is
# `(byte[off] & mask) + off` in both layers -- the field-4 pages ($F7E3/$F845)
# and the bank-5 content stream ($88D0) use the same rule with different leads.
FIELD4_SHAPE = {0x80: (7, 0x7F), 0xC1: (9, 0x1F)}
STREAM_SHAPE = {0x82: (7, 0x7F),        # $89CF
                0x81: (8, 0x1F)}        # $89C2
# $80, $A0, '(', '<' and '{' route into handlers that need machine state this
# harness does not model; their lengths are NOT established -- do not guess.


def build_content(tokens=b"", b0=0x82, b1=0x80, extra=b""):
    """What follows the record terminator: the `$87AF` header, then tokens.

    `b1`'s low nibble is the header's own length (`count = (b1 & $0F) + 2`),
    so `extra` must match it.  `b1 = $80` gives the minimal two-byte header.
    """
    if len(extra) != (b1 & 0x0F):
        raise ValueError(f"b1 = ${b1:02X} declares {(b1 & 0x0F)} extra header "
                         f"byte(s), got {len(extra)}")
    return bytes([b0, b1]) + extra + bytes(tokens)


def stream_token(lead=0x82, payload=b""):
    """One bank-5 content-stream token (`$88D0`)."""
    return _token(lead, payload, STREAM_SHAPE)


# The eight-byte text-token header.  Two REAL examples live in bank 5, and they
# are the ground truth for this -- reading the handlers alone got the field
# offsets right but the encoding wrong:
#
#   $BB23  80 81 85 8c d7 84 80 80   "A B C D E … 1 2 3 4 5 …"  (the keyboard)
#   $BB83  80 81 85 99 97 84 80 80   half-width katakana
#
#   byte[0]  $80   lead
#   byte[1]  $81   the DRAW CONDITION, and the token's PANE number.  Low 5 bits
#                  are maxed into $C3 ($8279) unless bit $40 is set; $C3 is then
#                  the pane count and $B8 the pane on screen.  See PANE_ below.
#                  BOTH ROM tokens use 1, i.e. "pane 1 of a one-pane page".
#   byte[2]  $80|col   tile column ($9234 scales by 8); both use 5
#   byte[3]  $80|row   tile row -- 25 and 12, the two that differ
#   byte[4]  $80|(w-1) low 5 bits are the field width in columns; both 23 (=24
#                      columns).  Bit $40 differs between them ($97 vs $D7).
#   byte[5]  $84   constant in both; never read via ($B0),Y
#   byte[6]  $80   constant in both; never read via ($B0),Y
#   byte[7]  $80   & $7F == 0, which is what puts $8957 in text mode
#
# EVERY BYTE HAS BIT 7 SET, like the rest of this format.  serve9 sent
# `80 18 04 06 17 80 80 00` -- right offsets, bit 7 clear on four of them and a
# byte[1] of 24 instead of 1 -- and the card drew a single widget glyph.
TEXT_LEAD = 0x80
TEXT_HDR_B1 = 0x81          # $BB23/$BB83
TEXT_HDR_B5 = 0x84
TEXT_HDR_B6 = 0x80
TEXT_HDR_B7 = 0x80

# ---- byte[1], the draw condition -- and why a page has PAGES ---------------
#
# `$8CB9` loads the condition byte into `$E0` (byte[1] for a `$8x`/`$9x` lead,
# byte[2] for a `$Cx` -- the `BIT $01A0` at `$8CDF` picks Y) and `$8DB2` rules:
#
#     bit $40 clear : draw iff (b & $1F) == $B8
#     bit $40 set   : bit $20 set -> require $C3 bit 7
#                     bit $10 set -> draw iff $B8 >= 2
#                     otherwise   -> draw
#
# `$B8` is the PANE ON SCREEN, and byte[1]'s low five bits are the pane a token
# belongs to:
#
#   $80B7  seeds $C3 = 1, $CE = 1                  ; pass 5 entry
#   $8279  $C3 = max($C3, byte[1] & $1F)           ; per token, if bit $40 clear
#   $810C  $C3 = max($C3, $CE); $B8 = 1            ; end of pass 5
#          $C3 == 1 -> $C3 |= $80                  ; ...and if $D4, $B8 = $C3
#   $9AE4  RIGHT $55 returns early iff $B8 == ($C3 & $7F)
#   $9AEE  LEFT  $54 returns early iff $B8 == 1
#   $9AFB  otherwise $BE = 4 -> $8078: INC/DEC $B8, then $BE = 6, full redraw
#   $80A4  $B8 == $C3 -> $C3 |= $80, and nothing clears it again
#
# So `$C3 & $7F` is the pane COUNT, tallied from the tokens themselves, and
# `$C3` bit 7 is a one-way "has reached the last pane" latch -- PANE_SEEN_LAST
# means "has read to the end", not "is on the last pane", and there is no form
# for the latter.  A one-pane page sets the bit at $8132, which is what makes
# ◀/▶ inert unless a page opts in.  ◀ and ▶ are silkscreened 前ページ / 次ページ
# (HVC-051_KEYMAP.md).
PANE = lambda n: n & 0x1F           # draw only on pane n
PANE_ALWAYS = 0x40                  # draw on every pane
PANE_SEEN_LAST = 0x60               # draw once the last pane has been reached
PANE_NOT_FIRST = 0x50               # draw on any pane but the first


# The two full-width symbols the card draws from the adapter's font ROM, as a
# Shift-JIS pair rather than a JIS X 0201 byte.  Two columns each, which is what
# `cells()` already counts -- one per byte.  Only a NARROW token forbids them
# ($7109 bit 5 -> $D787's $02 bit 6 -> $DD1B is never consulted); bank 1's own
# page titles are `$81 $9F <title> $81 $9F`, a ◆ at each end (`$967D`).
FULLWIDTH = {"◆": b"\x81\x9f", "◇": b"\x81\x9e"}
# `$85 $40`-`$4F` is the card's own full-width set: `$DA53` shortcuts that lead
# to a 16-entry table of 32-byte glyphs at bank 7 `$CEAD`, so these never reach
# the font ROM.  `$46`-`$4F` are the roman numerals Ⅰ-Ⅹ the supplement (p.2)
# announces; `$40`-`$45` are hardware labels, in HW below.
FULLWIDTH.update({chr(0x2160 + i): bytes([0x85, 0x46 + i]) for i in range(10)})

# One glyph, not two letters: `$CEAD` entries 0-5.  The crowned FC and GB are
# drawn in a framed box and the manual never uses them; SFCD is `CD` over `SF`.
HW = {"SFCD": b"\x85\x40", "SF": b"\x85\x41", "FC-crown": b"\x85\x42",
      "FC": b"\x85\x43", "GB-crown": b"\x85\x44", "GB": b"\x85\x45"}

# `{NAME}` in any text is one of these glyphs, asked for by name: a page writes
# `Final Fantasy {IV}` and `Mega Man X` keeps its letter, which no rule over
# bare `I`/`V`/`X` could do.  An unknown name stays exactly as it was typed, so
# `{answer}` and friends pass through untouched.
GLYPH = dict(HW)
GLYPH.update({n: bytes([0x85, 0x46 + i]) for i, n in enumerate(
    ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X"))})

# The card's OWN half-width glyphs, below $20 and so nameless in JIS X 0201:
# `$DA27` draws `$00`-`$0F` from the 16-entry table at bank 7 `$CE8D` without
# touching the font ROM, 8x16 and one cell like any half-width byte.  `$02` is
# the V-sign that replaced the top-pick `*` (supplement p.2); `$03`-`$0F` are
# the kit behind its "graphs can now be drawn" -- `▉`/`█` a solid bar's head and
# body, `▒`/`░` the same dotted, `＿` the axis rule under them, `┌┐└┘▔▁` a frame
# around a line of text.  `$04` duplicates `$03` byte for byte and has no key.
CARDTILE = {"「": b"\x00", "」": b"\x01", "✌": b"\x02", "╱": b"\x03",
            "▉": b"\x05", "█": b"\x06", "＿": b"\x07",
            "┌": b"\x08", "┐": b"\x09", "▔": b"\x0a", "▁": b"\x0b",
            "┘": b"\x0c", "└": b"\x0d", "▒": b"\x0e", "░": b"\x0f"}
_EXTRA = {**FULLWIDTH, **CARDTILE}
_PAIRS = set(FULLWIDTH.values()) | set(HW.values())


def halfwidth(text, terminate=True):
    """Encode for the content page: **JIS X 0201, one byte per glyph.**

    This is NOT the login message's encoding.  `$B60D` lays out double-byte
    Shift-JIS; a narrow token's draw path emits one glyph per byte, so a
    Shift-JIS pair comes out as two characters.  Measured on hardware
    (`serve10`, a `$84` token): `83 65 83 58 83 67` (テスト) drew as `てeてXてg`.
    `FULLWIDTH` above is the exception, and only off narrow.

    `$DD1B` is why the ROM's own tokens use half-width: it reports a single
    byte for `$A0`-`$DF` and a pair only for the Shift-JIS lead ranges
    (`$81`-`$9F`, `$E0`-`$EB`), so half-width kana is the range where the
    length pass and the draw pass agree.  Bank 5 `$BB83` reads `ｽﾍﾟ-ｽ`
    ("SPACE", the on-screen keyboard's key label) under exactly this mapping.

    `CARDTILE` and `FULLWIDTH` map a character to a card glyph, and `{NAME}`
    asks for one of `GLYPH` by name.
    """
    out = bytearray()
    i = -1
    while (i := i + 1) < len(text):
        ch = text[i]
        if ch == "{":
            end = text.find("}", i)
            name = text[i + 1:end] if end > 0 else ""
            if name in GLYPH:
                out += GLYPH[name]
                i = end
                continue
        if ch == "\n":
            out += b"\x5c\xf0"      # the ROM's keyboard token breaks lines here
            continue
        if ch in _EXTRA:
            out += _EXTRA[ch]
            continue
        for part in unicodedata.normalize("NFD", ch):
            if part == "゙":
                out.append(0xDE)                    # ﾞ
                continue
            if part == "゚":
                out.append(0xDF)                    # ﾟ
                continue
            hw = _HALFWIDTH.get(part, part)
            if hw == "\\":
                out += b"\x5c\x5c"                  # $5C is the escape
                continue
            o = ord(hw)
            if 0x20 <= o < 0x7F:
                out.append(o)
            elif 0xFF61 <= o <= 0xFF9F:
                out.append(0xA1 + o - 0xFF61)
            else:
                raise ValueError(
                    f"{ch!r} has no JIS X 0201 form; the content page's font "
                    "is ASCII plus half-width katakana, one byte per glyph "
                    "(hiragana and kanji need the $B60D message path)")
    if terminate:
        out += b"\x5c\xfe"
    return bytes(out)


def wrapped(text, width, terminate=True):
    """`halfwidth(text)` with `$5C $F0` breaks placed at word boundaries.

    `$ACE4` wraps per character -- `$AF24` re-saves the position before
    every one, so the line ends exactly at the width and the word with it.  The
    card cannot be told otherwise, but a break we put in the stream ourselves
    costs two bytes and lands where we choose, so word wrapping is the server's
    job.

    Cells are counted the way `$AF1C` counts them: one per byte, including the
    `$DE`/`$DF` voiced marks, except that a `$5C` escape is free -- `$5C $3C`
    and `$5C $3E` only move `$CF`, and `$5C $5C` is the one that draws (a
    literal `$5C`, one cell).  A `$5C $F0` already in `text` (write `\\n`) is
    honored as a forced break.

    A word longer than `width` has nowhere to go and is split at the width,
    which is what the card would have done anyway.
    """
    body = halfwidth(text, terminate=False) if isinstance(text, str) \
        else bytes(text)
    if body.endswith(b"\x5c\xfe"):
        body = body[:-2]

    # --- split into cells, then into words ---------------------------------
    words, word, forced = [], [], False
    i = 0
    while i < len(body):
        b = body[i]
        if b == 0x5C and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == 0xF0:                 # a break the caller placed
                words.append((word, forced))
                word, forced = [], True
                i += 2
                continue
            # $5C $5C draws one cell; every other escape draws none
            word.append((body[i:i + 2], 1 if nxt == 0x5C else 0))
            i += 2
            continue
        if b == 0x20:
            words.append((word, forced))
            word, forced = [], False
            i += 1
            continue
        word.append((body[i:i + 1], 1))
        i += 1
    words.append((word, forced))

    # --- greedy fill -------------------------------------------------------
    lines, line, used = [], bytearray(), 0
    for cells, force in words:
        if force:
            lines.append(bytes(line))
            line, used = bytearray(), 0
        if not cells:                       # a run of spaces, or a bare break
            continue
        w = sum(c for _, c in cells)
        raw = b"".join(s for s, _ in cells)
        if used and used + 1 + w <= width:
            line += b" "
            used += 1
        elif used:
            lines.append(bytes(line))
            line, used = bytearray(), 0
        if w <= width:
            line += raw
            used += w
            continue
        for chunk, cw in cells:             # too long for any line: hard-split
            if used + cw > width:
                lines.append(bytes(line))
                line, used = bytearray(), 0
            line += chunk
            used += cw
    lines.append(bytes(line))

    out = b"\x5c\xf0".join(lines)
    return out + b"\x5c\xfe" if terminate else out


EMPH_ON = b"\x5c\x3c"       # $ACE4's `\<` -- $CF = 1, the emphasized ink
EMPH_OFF = b"\x5c\x3e"      # `\>`


def cells(body):
    """How many cells `body` draws, counted the way `$AF1C` counts them.

    A `$5C` escape is free except `$5C $5C`, which draws one.  `wrapped()` uses
    the same rule; anything sizing a token's slot 6 needs it too, or an
    emphasis escape inflates the width and pushes the run off its row.
    """
    if isinstance(body, str):
        body = halfwidth(body, terminate=False)
    if body.endswith(b"\x5c\xfe"):
        body = body[:-2]
    n = i = 0
    while i < len(body):
        if body[i] == 0x5C and i + 1 < len(body):
            n += 1 if body[i + 1] == 0x5C else 0
            i += 2
            continue
        n += 1
        i += 1
    return n


def clip(body, n, terminate=True):
    """The first `n` cells of `body`, never splitting a pair or a `$5C` escape."""
    if isinstance(body, str):
        body = halfwidth(body, terminate=False)
    if body.endswith(b"\x5c\xfe"):
        body = body[:-2]
    out, used, i = bytearray(), 0, 0
    while i < len(body):
        if body[i] == 0x5C and i + 1 < len(body):
            wide, step = 1 if body[i + 1] == 0x5C else 0, 2
        elif 0x81 <= body[i] <= 0x9F or 0xE0 <= body[i] <= 0xEB:
            wide, step = 2, 2
        else:
            wide, step = 1, 1
        if used + wide > n:
            break
        out += body[i:i + step]
        used += wide
        i += step
    return bytes(out) + (b"\x5c\xfe" if terminate else b"")


def _build_halfwidth_map():
    """Full-width katakana and ASCII -> their half-width forms, via NFKC."""
    m = {}
    for cp in range(0xFF01, 0xFF5F):                # full-width ASCII
        m.setdefault(unicodedata.normalize("NFKC", chr(cp)), chr(cp - 0xFEE0))
    for cp in range(0xFF61, 0xFFA0):                # half-width kana
        m.setdefault(unicodedata.normalize("NFKC", chr(cp)), chr(cp))
    return m


_HALFWIDTH = _build_halfwidth_map()


def _check_glyphs(body, style):
    """Refuse a Shift-JIS lead byte the token's style would draw as two."""
    i = 0
    while i < len(body):
        b = body[i]
        if 0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEB:
            pair = bytes(body[i:i + 2])
            if pair in _PAIRS and style & 0x06 != STYLE_NARROW:
                i += 2
                continue
            raise ValueError(
                f"${b:02X} at text offset {i} is a Shift-JIS lead byte: "
                "$DD1B makes the length pass count it as a pair, and off a "
                "narrow style $D787 draws it as one full-width glyph from the "
                f"adapter's font ROM. Use halfwidth() -- JIS X 0201, or one of "
                f"{''.join(FULLWIDTH)} on a style that is not STYLE_NARROW.")
        i += 1


def text_token(text, col=5, row=12, width=24, cond=1, style=TEXT_HDR_B5):
    """A `$80` text token, shaped like the ROM's own at bank 5 `$BB23`/`$BB83`.

    `text` is a str (encoded here) or raw bytes already carrying the `$5C`
    escapes -- build those with message.py, whose encoding this
    shares.  Defaults are the keyboard token's geometry, which is known to
    render on this card.

    `cond` is byte[1], the draw condition -- `PANE(n)` for a token that belongs
    to pane n, or one of `PANE_ALWAYS` / `PANE_SEEN_LAST` / `PANE_NOT_FIRST`.
    The default 1 is what both ROM tokens use and what every page served so far
    has carried: pane 1 of a single-pane page.

    `style` is canonical slot 8, defaulting to bank 5's own `$84` (narrow,
    palette 0); off narrow the text may also carry a `FULLWIDTH` symbol.
    """
    body = halfwidth(text) if isinstance(text, str) else bytes(text)
    if body[-2:] != bytes([0x5C, 0xFE]):
        raise ValueError("text must end with the $5C $FE marker")
    style &= 0x7F               # $84, the ROM's own, carries the format's bit 7
    _check_glyphs(body[:-2], style)
    if not 0 <= col <= 0x1F or not 0 <= row <= 0x7F:
        raise ValueError("col is 0..31 and row is 0..127 ($7F masks byte[3])")
    if not 1 <= width <= 0x20:
        raise ValueError("width-1 must fit five bits, so width is 1..32")
    if not 0 <= cond <= 0x7F:
        raise ValueError("cond is byte[1] & $7F: a pane number 1..31, or one "
                         "of PANE_ALWAYS / PANE_SEEN_LAST / PANE_NOT_FIRST")
    if not cond & 0x40 and not 1 <= cond <= 0x1F:
        raise ValueError("a pane number is 1..31 ($8DB2 compares it against "
                         "$B8, which $810C seeds at 1)")
    return bytes([TEXT_LEAD,
                  0x80 | cond,
                  0x80 | col,
                  0x80 | row,
                  0x80 | (width - 1),
                  0x80 | style, TEXT_HDR_B6, TEXT_HDR_B7]) + body


# ---- the canonical header, and the paragraph token -------------------------
#
# `$FAE1` normalizes the five drawable non-bracket leads into one 14-byte
# record at $718F, so `$84` and `$80` in the `$80` header above are not
# constants at all -- they are canonical slots 8 and 9, the style and fill
# bytes, which every renderer reads through $7197/$7198.  Card.header_map()
# reads the maps out of a ROM image, when there is one.
PARA_LEAD = 0xA0

STYLE_FULLWIDTH = 0x00      # $7197 & $06 == 0: $B651 expands to `$82 xx` pairs
STYLE_PLAIN = 0x02          # two rows per line, no expansion
STYLE_NARROW = 0x04         # one row per line; $D787 gets $7109 bit 5.  What
                            # bank 5's own tokens use, and what pairs with the
                            # one-glyph-per-byte JIS X 0201 encoding above.
STYLE_CAPS = 0x08           # $1C/$1D/$1E end caps on an emphasized run
STYLE_EMPHASIS = 0x10       # start with emphasis already on ($CF = 1)
STYLE_PALETTE = lambda n: (n & 3) << 5      # -> $AF07 = 40 40 C0 80 -> $53

FILL_RIGHT = 0x20           # $B4D2 pads on the left / truncates from the left
FILL_MASK = 0x40            # HIDE the value.  $B227 walks the run from the end,
                            # leaves trailing spaces, then replaces the first
                            # printable and everything before it with $26 --
                            # which is plain `&`, a key on the on-screen
                            # keyboard, not a box tile.  $B256 does the same to
                            # a $C1.  This is password masking; leave it clear
                            # to show what the field holds.  It also tells
                            # $B2B3 the value is already ASCII rather than
                            # binary nibbles needing ORA #$30 -- harmless
                            # either way for '0'-'9', which already carry $30.


def para_token(text, col=5, row=4, width=23, height=20, style=STYLE_NARROW,
               wrap=False):
    """An `$A0` paragraph token: a **wrapping, self-paginating** text block.

    Six header bytes and no length byte -- `$8995` finds the end by running
    `$ACE4` in measure mode (`$62 = 0`) and reading back where it stopped, so
    the text must end `$5C $FE` exactly as a `$80`'s does.

    Two things a `$80` cannot do.  `$A0` has a HEIGHT (canonical slot 7): when
    the text overflows `height` TILE ROWS -- a STYLE_PLAIN line costs two of
    them and a STYLE_NARROW line one -- `$AEBC` stops and `$AE66` moves it onto
    the next pane, and `$8995` reports that through `$CE` into the pane count,
    so ◀ ▶ turn the page.  And `$A0` has NO draw condition -- `$8CB9`
    draws any `$Ax` unconditionally -- so it cannot be confined to one pane.
    It has no slot 9 either, so no justification and no field fill.

    `width` and `height` are the counts `$ACE4` itself compares against
    (`$B02B`, `$AEF8`), NOT the `width - 1` that `text_token()` encodes for
    `$92EE`'s cursor box; an `$A0` has no cursor box.  A width of 23 draws 23
    characters per line, and a height of 12 fits six plain lines or twelve
    narrow ones (measured against the ROM: 6 lines, plain, height 6 -> 2 panes).

    THE CARD'S WRAP IS NOT WORD-AWARE.  `$AF24` re-saves the position before
    every character, so `$B04C` rewinds one character and the line breaks
    exactly at `width` -- mid-word, and between a kana and a following
    `$DE`/`$DF` voiced mark, which JIS X 0201 makes a character of its own.

    **`wrap=True` fixes that here**: `wrapped()` pre-breaks the text at word
    boundaries with `$5C $F0`, using this token's own `width`.  It is off by
    default because it rewrites the payload, and this file's other business is
    to build exactly the bytes it is asked for.  Two bytes a line, and the
    breaks then land where a reader expects them.
    """
    if wrap:
        text = wrapped(text, width)
    body = halfwidth(text) if isinstance(text, str) else bytes(text)
    if body[-2:] != bytes([0x5C, 0xFE]):
        raise ValueError("text must end with the $5C $FE marker")
    _check_glyphs(body[:-2], style)
    if not 0 <= col <= 0x1F or not 0 <= row <= 0x1F:
        raise ValueError("col is 0..31; row is 0..31 and $B011 masks it $1F, "
                         "with everything past row 26 clamped to $9A")
    if not 1 <= width <= 0x1F or not 1 <= height <= 0x1F:
        raise ValueError("width and height are five-bit counts, 1..31")
    if style & ~0x7F:
        raise ValueError("style is seven-bit; bit 7 is added here")
    return bytes([PARA_LEAD,
                  0x80 | col,
                  0x80 | row,
                  0x80 | width,
                  0x80 | height,
                  0x80 | style]) + body


# ---- the type-2 field: $C0 and $C1 ----------------------------------------
#
# `$C0` is `$80` plus a field and `$C1` is `$81` plus a field -- the extra byte
# is byte[1], which pushes the condition to byte[2] and carries the field's
# options.  `$824D` -> `$85C4` registers type 2 for either, and `$9C9B` is the
# key handler: it loads the token pointer out of the descriptor's byte[4]/[5],
# picks a mode from `$9C99` and calls `$A25C`, which splits on the lead --
# `$A3DE` for `$C0`, `$A27B` for `$C1`.
#
# What the two accept:
#
#   $C0, byte[1] bit $20 CLEAR   `.` opens the ON-SCREEN KEYBOARD ($A3FF draws
#                                the $930E record, sets $C6 = 1 and re-walks
#                                the stream); digits go straight in
#   $C0, byte[1] bit $20 SET     no keyboard.  digits, `.` and `*` are all
#                                taken as characters ($A457)
#   $C1                          digits, and `.` only when the token declares
#                                decimal places.  $A324 also refuses a LEADING
#                                zero when byte[1] bit $20 is set
#   both                         `C` ($44) clears the field ($A37B)
#
# Entry is right-to-left for the integer part ($A343 shifts the value left and
# writes the new character at the end, like a calculator), and positional in
# the fraction ($A36B).  `$62`'s low two bits are the mode `$9C9B` passes:
# bit 0 inserts, bit 1 clears first, and `& 3 == 2` is clear-only.
FIELD_LEAD_TEXT = 0xC0
FIELD_LEAD_NUMBER = 0xC1

FIELD_REQUIRED = 0x10   # $F9FA: EXECUTE refuses while the field still has fill
FIELD_DIRECT = 0x20     # $C0: no keyboard, and `.`/`*` are characters ($A457)
                        # $C1: fill with ' ' not '0', and refuse a leading zero
FIELD_VALIDATE = 0x40   # $FA0C/$FA11 check this field before EXECUTE


def _field_header(lead, cond, col, row, width, style, fill, options):
    for name, v, hi in (("cond", cond, 0x7F), ("col", col, 0x1F),
                        ("row", row, 0x1F), ("width", width, 0x1F),
                        ("style", style, 0x7F), ("fill", fill, 0x7F),
                        ("options", options, 0x7F)):
        if not 0 <= v <= hi:
            raise ValueError(f"{name} is 0..{hi}")
    if not cond & 0x40 and not 1 <= cond <= 0x1F:
        raise ValueError("cond is a pane number 1..31, or one of PANE_ALWAYS / "
                         "PANE_SEEN_LAST / PANE_NOT_FIRST")
    return [lead, 0x80 | options, 0x80 | cond, 0x80 | col, 0x80 | row,
            0x80 | width, 0x80 | style, 0x80 | fill]


def input_token(width, col=5, row=12, value=None, cond=1,
                style=STYLE_NARROW, fill=0, options=0):
    """A `$C0` text-entry field -- nine header bytes, then its value.

    `width` is the field's drawn width (canonical slot 6) and `value` is what
    it starts with, `width` bytes of it; the default is blanks.  `$894A` takes
    the length from byte[8] as `(n & $7F) + 8`, and `$FB15`/`$A3C2` mask the
    same byte with `$1F`, so the value is 1..30 characters.

    `fill` is canonical slot 9: `FILL_RIGHT` right-aligns, and `FILL_MASK`
    hides the value behind `&`.  `options` is byte[1]: see FIELD_REQUIRED,
    FIELD_DIRECT and FIELD_VALIDATE above.
    """
    body = halfwidth(value, terminate=False) if isinstance(value, str) \
        else bytes(value) if value is not None else b" " * width
    if not 1 <= len(body) <= 30:
        raise ValueError("a $C0 value is 1..30 bytes: byte[8] holds len + 1 "
                         "and $FB15 masks it with $1F")
    if ETX in body:
        raise ValueError("$03 in a value would truncate the block")
    return bytes(_field_header(FIELD_LEAD_TEXT, cond, col, row, width,
                               style, fill, options)
                 + [0x80 | (len(body) + 1)]) + body


def number_token(integer, decimals=0, col=5, row=12, width=None, value=None,
                 cond=1, style=STYLE_NARROW, fill=0, options=0,
                 number=0):
    """A `$C1` numeric field -- eleven header bytes, then its digits.

    `integer` and `decimals` are how many digit positions sit either side of
    the point; `$FB15` derives the split the same way, as
    `(slot 12 & $1F) - 2 - decimals`.  `width` defaults to what the formatted
    value needs, a point included.

    `number` is canonical slot 10, the format byte `$B19D` reads: grouping,
    the pad character and the keep-leading-zeros bit.
    """
    n = integer + decimals
    if not 1 <= n <= 29:
        raise ValueError("a $C1 carries 1..29 digits: byte[9] holds len + 2 "
                         "and $FB15 masks it with $1F")
    if not 0 <= decimals <= 0x1F:
        raise ValueError("decimals is canonical slot 13, five bits")
    if width is None:
        width = n + (1 if decimals else 0)
    pad = b" " if options & FIELD_DIRECT else b"0"
    body = bytes(value) if value is not None else pad * n
    if len(body) != n:
        raise ValueError(f"value is {len(body)}B, must be {n} digits")
    if ETX in body:
        raise ValueError("$03 in a value would truncate the block")
    return bytes(_field_header(FIELD_LEAD_NUMBER, cond, col, row, width,
                               style, fill, options)
                 + [0x80 | (number & 0x7F), 0x80 | (n + 2), 0x80 | decimals]
                 ) + body


# ------------------------------------------------------------------- brackets
#
# The stream is a TREE.  `(`, `<` and `{` are brackets, and their closers --
# `)` `$29`, `>` `$3E`, `}` `$7D` -- and separator `;` `$3B` never reach
# `$881D`, because the bracket handlers consume them from inside (`$8924`,
# `$8A4C`, `$8A6F`).  That is why they are absent from the `$FBAF` token table,
# and why a bare `)` in the stream is `4980`.
#
# The FIRST child of any bracket must have a lead byte `>= $80` (`$880C` ->
# **4987**, and that one is NOT gated on `$BD`), so a bracket cannot open with
# a nested bracket.  After a `;` the same check is `$8808`, which only fires
# when `$BD` is set.
#
# A `(` carries a mode byte at offset 1 and `$8833` accepts only five shapes;
# anything else is **4981**.  Bits 4-6 pick the flavor, and the advance pass
# (`$8924`), the draw pass (`$8C23`) and the measure pass (`$8215`) agree:
#
#   $8n  flavor 0  $89DC / $8D55 / $829A   n alternatives, `;` between them
#   $90  flavor 1  $8A16 / $8D24 / $834B   two-byte header
#   $91  flavor 1  $8A16 / $8D24 / $834B   three-byte header (extra byte at 2)
#   $An  flavor 2  $8A16 / $8C6B / $842B   switch: only child n is drawn
#   $B0  flavor 3  $8A16 / $8C45 / $84A2   plain group
#
# What each registers in $71D7, read off the measure handlers and confirmed by
# Card.measure() against the ROM:
#
#   flavor 0  ONE type-5 field for the group      keys: Left/Right   ($9C28)
#   flavor 1  ONE field PER CHILD -- type 4 for   keys: none ($9DB3 is an RTS)
#              $90 (stride 6), type 8 for $91
#              (stride 8, byte[4]/[5] = the `(`)
#   flavor 2  ONE type-3 field, byte[6] = the     keys: `#` $23      ($9D37)
#              child count, byte[7] = b1 & $0F
#   flavor 3  ONE type-6 field                    keys: Left/Right   ($9C28)
#   `<`        ONE type-1 field                    keys: Left/Right + C $44
#   `{`        ONE type-7 field                    keys: none ($9B54 is an RTS)
GROUP_OPEN, GROUP_CLOSE, GROUP_SEP = 0x28, 0x29, 0x3B
ANGLE_OPEN, ANGLE_CLOSE = 0x3C, 0x3E
BRACE_OPEN, BRACE_CLOSE = 0x7B, 0x7D


def _group_header(b1):
    """`$8833`, and the lead-in `$8A16`/`$8D24` agree on: 3 for `$91`, else 2."""
    if 0x80 <= b1 <= 0x8F or 0xA0 <= b1 <= 0xAF or b1 in (0x90, 0xB0):
        return 2
    if b1 == 0x91:
        return 3
    raise ValueError("$8833 accepts only $8n, $90, $91, $An and $B0 as a "
                     "group mode byte; $%02X is 4981" % b1)


def _children(children, what="group"):
    body = (bytes(children) if isinstance(children, (bytes, bytearray))
            else b"".join(bytes(c) for c in children))
    if not body:
        raise ValueError("an empty %s has no first child, and $880C demands "
                         "a lead byte >= $80 there" % what)
    if body[0] < 0x80:
        raise ValueError("a %s must open with a lead byte >= $80, not $%02X "
                         "($880C -> 4987)" % (what, body[0]))
    return body


def group(children, b1=0xB0, extra=b""):
    """A `(`...`)` group.  `children` is a token, or an iterable of tokens."""
    head = _group_header(b1)
    if len(extra) != head - 2:
        raise ValueError("mode $%02X declares a %d-byte header, so extra must "
                         "be %d byte(s)" % (b1, head, head - 2))
    return (bytes([GROUP_OPEN, b1]) + bytes(extra)
            + _children(children) + bytes([GROUP_CLOSE]))


def option_group(alternatives, selected=1):
    """The **option cycler** -- flavor 0, and the one widget that is decoded.

    `alternatives` is a list of tokens, one per choice, `;`-separated on the
    wire.  The measure pass (`$829A`) registers a **type-5 field** in `$71D7`:

        byte[4]/byte[5]  a pointer back to this `(`, high byte first
        byte[6]          the number of alternatives -- COUNTED by the card
        byte[7]          `b1 & $0F`, the initial selection
        byte[3]          5 (`| $80` when the group is nested)

    and in pass 7 `$9C28` maps **Left `$50` / Right `$53`** onto byte[7],
    wrapping 1..byte[6].  `$91BD` redraws it: it decrements byte[7] once per
    **`;`** (`$91EA`), skipping any further tokens inside an alternative
    without counting them (`$91E8`), so the index really is the alternative
    number and an alternative may hold more than one token.

    All of that is confirmed on hardware 2026-08-09, and so are two things the
    2026-08-08 write-up got wrong:

      * **Every alternative is drawn**, not just the selected one (`$8D55`
        walks the group).  Alternatives normally share a column and row, so
        they overwrite each other and only the last is visible -- which is why
        a page can look like it is drawing one option when it is drawing all
        of them.  Give them different rows and all of them appear.
      * **The cycler works without the `$F1` cursor record.**  Left / Right
        step the selection, and the bracket highlight moves with it.  The
        earlier "an unarmed group drops every keypress" was an artifact of
        drawing all the alternatives on one row: the highlight had nowhere
        visible to go.
      * Two markers, easily confused: the **brackets** are the selection inside
        a group, the **left-edge arrow** is which field is current (drawn on
        its anchor row, moved by Up / Down -- see `Card.measure`).  A field's
        row does not change as its selection is cycled.

    So `Card.measure()`'s `interactive` is NOT a "does the D-pad work" flag --
    see its docstring.  A plain group of single tokens is a working cycler.
    """
    alts = [_children(a, "alternative") for a in alternatives]
    if not alts:
        raise ValueError("an option group needs at least one alternative")
    if not 1 <= selected <= min(len(alts), 0x0F):
        raise ValueError("selected is 1..%d here (it is b1's low nibble, and "
                         "$9C28 wraps it against the card's own count)"
                         % min(len(alts), 0x0F))
    return group(bytes([GROUP_SEP]).join(alts), b1=0x80 | selected)


def switch_group(children, selected=1):
    """A `(`...`)` **switch** -- flavor 2, `$An`.

    `$8C6B` draws only child number byte[7]; `$842B` registers a **type-3**
    field whose byte[6] is the child count it tallies itself and whose byte[7]
    is `b1 & $0F` (forced to 1 when the nibble is 0).

    Type 3 is not reached through the per-field key table at all.  `$9B00`
    special-cases the key **`#` (`$23`)** at `$9B08` and jumps straight to
    `$9D37`, which follows `$CC`/`$CD` -- the pointer `$96B6` captured for the
    one descriptor whose byte[3] is `$03` -- steps byte[7] with wrap, writes the
    new value back into the group's mode byte in the stream, and redraws via
    `$8C6B`.  So `#` cycles the switch whatever field the cursor is on, and a
    page has at most one switch.

    Unlike the flavor-0 cycler, the children are NOT `;`-separated and only the
    selected one is drawn -- so they SHOULD share a row.
    """
    kids = [_children(c, "switch child") for c in children]
    if not kids:
        raise ValueError("a switch needs at least one child")
    if not 1 <= selected <= min(len(kids), 0x0F):
        raise ValueError("selected is 1..%d ($842B stores b1 & $0F, and $9D37 "
                         "wraps it against the child count)"
                         % min(len(kids), 0x0F))
    return group(b"".join(kids), b1=0xA0 | selected)


def angle_group(children):
    """`<`...`>` (`$8A4C` / `$8CFE`) -- a **horizontal selector**, type 1.

    Left/Right step it and **C `$44`** resets it to the first child (`$9C22` is
    the flavor-0 cycler `$9C28` with that one key in front).

    **Lay the children out ACROSS a row, at different columns.**  The markers
    are sprites: `$9273` puts a box at (col-1, row) for every child and `$9244`
    puts the selection pointer at (col-1, row+1) for the chosen one, so children
    stacked on consecutive rows collide with each other's markers.  That is the
    opposite of `option_group`, whose alternatives overlap unless separated.
    """
    return bytes([ANGLE_OPEN]) + _children(children, "<> group") + bytes([ANGLE_CLOSE])


def brace_group(children):
    """`{`...`}` (`$8A6F` / `$8CA1`).  Registers a **type-7** field (`$8513`).

    Inert in every sense: `$8CA1` draws only the first child, `$9B54` is an
    `RTS`, and `$96B6` leaves it out of the `$71BA` cursor map, so Up/Down steps
    straight past it.  A wrapper, not a widget.
    """
    return bytes([BRACE_OPEN]) + _children(children, "{} group") + bytes([BRACE_CLOSE])


def token(lead=0x80, payload=b""):
    """One field-4 token (`$F7E3`)."""
    return _token(lead, payload, FIELD4_SHAPE)


def _token(lead, payload, shapes):
    if lead not in shapes:
        raise ValueError("lead byte must be one of "
                         + ", ".join("$%02X" % k for k in shapes))
    head, mask = shapes[lead]
    n = len(payload) + 1
    if n & ~mask:
        raise ValueError("payload too long for a $%02X token" % lead)
    if n in (ETX, EOT):
        raise ValueError("a length byte of $%02X would truncate the record" % n)
    return bytes([lead]) + bytes(head - 1) + bytes([n]) + bytes(payload)


# ---------------------------------------------------------------- self-test

def _corpus():
    """Every shape the builders can emit, as (records, content blocks)."""
    records = [
        ("minimal", [{"name": 0x81, "items": [(0x81, 0x7F)]}]),
        ("inline name", [{"name": b"MARIO CLUB      ",
                          "items": [(0x81, 0x7F)]}]),
        ("two entries", [{"name": 0x81, "items": [(0x81, 0x7F)]},
                         {"name": 0x82, "items": [(0x83, 0x80)]}]),
        ("eight items", [{"name": 0x81,
                          "items": [(0x81 + i, 0x7F) for i in range(8)]}]),
        ("sixteen entries", [{"name": 0x81, "items": [(0x81, 0x7F)]}] * 16),
        ("field-3 record", [{"name": 0x81,
                             "items": [(submenu_record("013", "X"), 0x7F)]}]),
        ("field-4 page", [{"name": 0x81, "page": token(0x80, b"ABCDE"),
                           "items": [(0x81, 0x7F)]}]),
        ("all of it", [{"name": b"MARIO CLUB      ",
                        "items": [(0x81, 0x7F), (0x8B, 0x80)]},
                       {"name": 0x82, "page": token(0x80, b"ABCDEF"),
                        "items": [(submenu_record("013", "INLINE"), 0x7F)]}]),
    ]
    out_rec = []
    for what, entries in records:
        out_rec.append((what, build_record(entries)))
        out_rec.append((what + ", naked",
                        build_record(entries, term=None) + bytes([ETX])))

    tokens = [
        ("text", text_token("HELLO")),
        ("paragraph", para_token("A LONGER PARAGRAPH OF TEXT THAT WRAPS")),
        ("entry field", input_token(8)),
        ("numeric field", number_token(4, 2)),
        ("option cycler", option_group([text_token("A"), text_token("B")])),
        ("switch", switch_group([text_token("A"), text_token("B")])),
        ("checkbox group", angle_group([text_token("A"), text_token("B")])),
        ("brace group", brace_group([text_token("A")])),
        ("$91 group", group(text_token("A"), b1=0x91, extra=b"\x83")),
    ]
    out_blk = [(w, build_content(t)) for w, t in tokens]
    out_blk.append(("every token", build_content(b"".join(t for _, t in tokens))))
    return out_rec, out_blk


def _model_selftest():
    """The ROM-free checks: everything the builders emit must be accepted."""
    model, ok = CardModel(), True
    recs, blks = _corpus()
    print("the model accepts every builder output:")
    for what, rec in recs:
        err = model.parse(rec)["error"]
        ok &= err is None
        print("  %s record %-24s %s" % ("ok " if err is None else "FAIL",
                                        what, err or "accepted"))
    for what, blk in blks:
        err = model.check_content(blk)["error"]
        ok &= err is None
        print("  %s block  %-24s %s" % ("ok " if err is None else "FAIL",
                                        what, err or "accepted"))

    print("the model rejects a malformed record:")
    for what, rec, want in (
            ("name byte < $80", b"\x30\x7f\x81\x7f" + b"/" * 4 + b"\x03", "4940"),
            ("action byte invalid", b"\x81\x30\x81\x7f" + b"/" * 4 + b"\x03", "4941"),
            ("item selector < $80", b"\x81\x7f\x30\x7f" + b"/" * 4 + b"\x03", "4942"),
            ("item parameter < $7F", b"\x81\x7f\x81\x30" + b"/" * 4 + b"\x03", "4943"),
            ("no items", b"\x81\x7f" + b"/" * 4 + b"\x03", "4945"),
            ("17 entries", _many_entries(17), "494A"),
            ("9 items", _many_items(9), "494B")):
        got = model.parse(rec)["error"]
        ok &= got == want
        print("  %s %-24s want %-6s got %s"
              % ("ok " if got == want else "FAIL", what, want, got))

    print("the model rejects a malformed block:")
    for what, blk, want in (
            ("bad trailer b0", b"\x30\x80", "4970"),
            ("bad trailer b1", b"\x80\x30", "4971"),
            ("lead byte < $80", b"\x82\x80\x30", "4980"),
            ("unknown lead byte", b"\x82\x80\xb5", "4988"),
            ("bad group mode", b"\x82\x80\x28\x30", "4981"),
            ("bracket opens on a closer", b"\x82\x80\x28\xb0\x29", "4987")):
        got = model.check_content(blk)["error"]
        ok &= got == want
        print("  %s %-24s want %-6s got %s"
              % ("ok " if got == want else "FAIL", what, want, got))
    return ok


def _crosscheck(card):
    """Model against the card itself: identical verdicts on builder output."""
    model, ok = CardModel(), True
    recs, blks = _corpus()
    for what, rec in recs:
        a, b = card.parse(rec)["error"], model.parse(rec)["error"]
        ok &= a == b
        if a != b:
            print("  FAIL record %-24s rom %s, model %s" % (what, a, b))
    for what, blk in blks:
        a = card.check_content(blk)["error"]
        b = model.check_content(blk)["error"]
        ok &= a == b
        if a != b:
            print("  FAIL block  %-24s rom %s, model %s" % (what, a, b))
    print("  %s the model agrees with the ROM on all %d builder outputs"
          % ("ok " if ok else "FAIL", len(recs) + len(blks)))
    return ok


def _selftest():
    ok = _model_selftest()
    print()
    if not rom_path():
        print("ROM cross-check: skipped -- no image (set $SMC_ROM to a dump "
              "of your own cartridge to run the card's own code)")
        print("SELF-TEST", "PASSED" if ok else "FAILED")
        return 0 if ok else 1
    print("== the card's own code, against %s ==" % rom_path())
    ok &= _crosscheck(Card())
    return _rom_selftest(ok)


def _rom_selftest(ok=True):
    card = Card()

    def check(what, record, want):
        nonlocal ok
        got = card.parse(record)["error"]
        flag = "ok " if got == want else "FAIL"
        if got != want:
            ok = False
        print("  %s %-34s want %-6s got %s" % (flag, what, want, got))

    # A minimal well-formed record: one entry, ROM name $81, no page, one item.
    good = build_record([{"name": 0x81, "items": [(0x81, 0x7F)]}])
    print("minimal record:", good.hex(" "))
    res = card.parse(good)
    print("  parse ->", res["error"], "entries:", res["entries"])
    if res["error"] is not None or res["entries"] != 1:
        ok = False
        print("  FAIL: the minimal record must parse")
    else:
        line = res["buffers"]["lines"][:22]
        print("  line 0:", line.hex(" "), "|" + _sjis(line) + "|")
        if line != b"      " + card.names(1)[0]:
            ok = False
            print("  FAIL: display line is not 6 spaces + the ROM name")

    print("the thirteen errors:")
    check("4940 name byte < $80",
          b"\x30\x7f\x81\x7f" + b"/" * 4 + b"\x03", "4940")
    check("4941 action byte invalid",
          b"\x81\x30\x81\x7f" + b"/" * 4 + b"\x03", "4941")
    check("4942 item selector < $80",
          b"\x81\x7f\x30\x7f" + b"/" * 4 + b"\x03", "4942")
    check("4943 item parameter < $7F",
          b"\x81\x7f\x81\x30" + b"/" * 4 + b"\x03", "4943")
    check("4944 record starts with a separator",
          b"/" + b"\x81\x7f\x81\x7f" + b"/" * 3 + b"\x03", "4944")
    # Only the '*' path checks the item count, so it takes a non-final entry.
    check("4945 entry with no items",
          b"\x81\x7f*\x81\x7f\x81\x7f" + b"/" * 4 + b"\x03", "4945")
    check("4946 field 2 not exhausted",
          b"\x81\x7f\x81\x7f/" + b"x" * 16 + b"///\x03", "4946")
    check("4947 field 3 not exhausted",
          b"\x81\x7f\x81\x7f//" + b"y" * 25 + b"//\x03", "4947")
    check("4948 field 4 missing its '/'",
          b"\x81\x7f\x81\x7f" + b"/" * 3 + b"\x03", "4948")
    check("494A a 17th entry",
          _many_entries(MAX_ENTRIES + 1), "494A")
    check("494B a 9th item in one entry",
          _many_items(MAX_ITEMS + 1), "494B")
    check("494C a %dth field-3 record" % (MAX_FIELD3 + 1),
          _many_f3(MAX_FIELD3 + 1), "494C")
    if card.parse(_many_f3(MAX_FIELD3))["error"] is not None:
        ok = False
        print("  FAIL: %d field-3 records must still be legal" % MAX_FIELD3)

    # 4949 -- a field-4 page whose tokens step past the record terminator.
    # The scan stops on $03, so pad W-RAM past the record with $03 first.
    for a in range(RECORD_ADDR + 0x40, RECORD_ADDR + 0x200):
        card.write(a, ETX)
    over = b"\x81\x80\x81\x7f" + b"///" + b"\x80\x00\x00\x00\x00\x00\x00\x7f" + b"/\x03"
    check("4949 page runs past the terminator", over, "4949")

    # A record that exercises every construct at once.
    rich = build_record([
        {"name": 0x81, "items": [(0x81, 0x7F), (0x82, 0xFF)]},
        {"name": b"\x81\xb2" + "テスト".encode("shift_jis") + b" " * 8,
         "page": token(0x80, b"\x00\x01\x02\x05") + token(0xC1, b"\x00"),
         "items": [(b"\xff" * FIELD3_LEN, 0x80)]},
        {"name": 0x8A, "action": 0xC3, "items": [(0x83, 0x7F)]},
    ])
    print("rich record (%d bytes): %s" % (len(rich), rich.hex(" ")))
    res = card.parse(rich)
    print("  parse ->", res["error"], "entries:", res["entries"])
    if res["error"] is not None or res["entries"] != 3:
        ok = False
        print("  FAIL: the rich record must parse")
    else:
        b = res["buffers"]
        print("  action bytes:", b["action"][:3].hex(" "),
              " item counts:", b["counts"][:3].hex(" "))
        print("  items[0]:", b["items"][:4].hex(" "))
        for i in range(3):
            print("  line %d: |%s|" % (i, _sjis(b["lines"][i * 22:(i + 1) * 22])))
        for i, p in enumerate(b["pages"]):
            print("  page %d: %s" % (i, p.hex(" ")))
        if len(b["pages"]) != 1:
            ok = False
            print("  FAIL: expected exactly one content page")

    # ---- inline sub-menu records, resolved the way $F507 resolves them ----
    print("inline sub-menu records ($F507: item < $80 -> $7AA0 + 25*ordinal):")
    dirn = card.page_titles()
    if dirn[0] != (b"001", "株式時価") or dirn[8][1] != "業績予想変更リスト":
        ok = False
        print("  FAIL: the directory base is not $87F0 -- titles come out cut")
    else:
        print("  ok  $87F0 + 25n: %s %s ... %s %s"
              % (dirn[0][0].decode(), dirn[0][1],
                 dirn[30][0].decode(), dirn[30][1]))

    inline = [submenu_record("013", "ソフトカレンダ"),
              submenu_record("014", "ソフトデータベース")]
    res = card.parse(build_record(
        [{"name": 0x81, "items": [(inline[0], 0x7F), (inline[1], 0xFF)]}]))
    if res["error"] is not None:
        ok = False
        print("  FAIL: an inline record must parse:", res["error"])
    else:
        got = res["buffers"]["items"][:4]
        arena = bytes(card.wram[0x7AA0 - 0x6000:0x7AA0 - 0x6000 + 50])
        placed = [arena[n * PAGE_DIR_LEN:(n + 1) * PAGE_DIR_LEN]
                  for n in range(2)]
        if got != b"\x00\x7f\x01\xff" or placed != inline:
            ok = False
            print("  FAIL: items %s, arena %s" % (got.hex(" "), placed))
        else:
            print("  ok  items %s -- ordinals 0,1 into the $7AA0 arena"
                  % got.hex(" "))
            for n, rec in enumerate(placed):
                print("      $%04X code %s title %s"
                      % (0x7AA0 + n * PAGE_DIR_LEN,
                         rec[:PAGE_CODE_LEN].decode(),
                         _sjis(rec[PAGE_CODE_LEN:]).strip()))

    # The unterminated form: no terminator on the wire, the card's own $03.
    naked = build_record([{"name": 0x81, "items": [(0x8B, 0x7F)]}], term=None)
    res = card.parse(naked + bytes([ETX]))
    ptr = card.read(0xB8) | card.read(0xB9) << 8
    if res["error"] is not None or card.read(ptr) != ETX:
        ok = False
        print("  FAIL: an unterminated record must take $FE7A's $03 branch")
    else:
        print("  ok  term=None -> $B8 lands on the card's own $03 ($A847, and "
              "$6E80 stays 0)")

    for what, bad in (("a 24-byte title", ("013", "x" * 23)),
                      ("a 2-digit code", ("13", "x")),
                      ("'/' in the title", ("013", "a/b"))):
        try:
            submenu_record(*bad)
        except ValueError:
            print("  ok  the builder refuses %s" % what)
        else:
            ok = False
            print("  FAIL: %s was accepted" % what)

    # ---- the brackets, walked by the card's own $88D0 --------------------
    print("brackets (the stream is a tree):")

    def stream(what, tokens, want=None):
        nonlocal ok
        r = card.check_content(build_content(tokens))
        got = r["error"]
        if got != want:
            ok = False
        n = r["walk"] and len(r["walk"]["tokens"])
        print("  %s %-40s want %-6s got %-6s %s"
              % ("ok " if got == want else "FAIL", what, want, got,
                 "" if n is None else "(%d top-level token%s)" % (n, "" if n == 1 else "s")))

    one = text_token("A")
    stream("a bare text token", one)
    stream("a ')' with no group", one + bytes([GROUP_CLOSE]), "4980")
    stream("an illegal group mode $92",
           bytes([GROUP_OPEN, 0x92]) + one + bytes([GROUP_CLOSE]), "4981")
    stream("a group opening with a group",
           bytes([GROUP_OPEN, 0xB0]) + group(one) + bytes([GROUP_CLOSE]), "4987")
    stream("a plain group $B0", group([one, text_token("B")]))
    stream("a switch group $A2", group([one, text_token("B"), text_token("C")], b1=0xA2))
    stream("a $91 group (three-byte header)", group(one, b1=0x91, extra=b"\x80"))
    stream("a <> group", angle_group(one))
    stream("a {} group", brace_group([one, text_token("B")]))
    stream("a group nested after a first child",
           group([one, option_group([text_token("B"), text_token("C")])]))

    cycler = option_group([text_token(s) for s in ("YES", "NO", "MAYBE")])
    stream("the option cycler, 3 alternatives", cycler)
    walk = card.check_content(build_content(cycler))["walk"]
    if walk["tokens"] != [(0, GROUP_OPEN, len(cycler))]:
        ok = False
        print("  FAIL: $88D0 must swallow the whole group as one token")
    else:
        print("  ok  $88D0 swallows the group whole: %d bytes" % len(cycler))
    for bad, why in ((0, "selected=0"), (4, "selected past the alternatives")):
        try:
            option_group([one, text_token("B"), text_token("C")], selected=bad)
        except ValueError:
            print("  ok  the builder refuses %s" % why)
        else:
            ok = False
            print("  FAIL: %s must be refused" % why)

    # ---- the field table the measure pass builds -------------------------
    print("the $71D7 field table ($80B7):")

    def measured(what, tokens, kinds, interactive):
        nonlocal ok
        m = card.measure(build_content(tokens))
        got = [f["kind"] + ("/t%d" % f["type"] if f["kind"] == "field" else "")
               for f in m["fields"]]
        good = m["error"] is None and got == kinds and m["interactive"] is interactive
        if not good:
            ok = False
        print("  %s %-40s %-22s interactive=%-5s %s"
              % ("ok " if good else "FAIL", what, ",".join(got) or "-",
                 m["interactive"], m["error"] or ""))
        return m

    alts = [text_token(s, col=12, row=14, width=8) for s in ("A", "B", "C")]
    spacer = text_token(" ", col=21, row=14, width=1)
    measured("a lone text token registers nothing", text_token("A"), [], False)
    flat = measured("a flat cycler: one type-5 field", option_group(alts),
                    ["field/t5"], False)
    armed = measured("...with a 2-token alternative: + cursor",
                     option_group([[alts[0], spacer], [alts[1]], [alts[2]]]),
                     ["field/t5", "cursor"], True)
    measured("a nested bracket arms it too",
             option_group([[alts[0], brace_group(spacer)], [alts[1]], [alts[2]]]),
             ["field/t5", "field/t7", "cursor"], True)

    two = [text_token("X", col=5, row=18), text_token("Y", col=5, row=20)]
    measured("a switch $An: one type-3 field", switch_group(two), ["field/t3"], False)
    measured("flavor 1 $90: one type-4 PER CHILD",
             group(two, b1=0x90), ["field/t4", "field/t4"], False)
    measured("flavor 1 $91: one type-8 per child",
             group(two, b1=0x91, extra=b"\x80"), ["field/t8", "field/t8"], False)
    measured("flavor 3 $B0: one type-6 field", group(two), ["field/t6"], False)
    measured("<> : one type-1 field", angle_group(two), ["field/t1"], False)
    measured("{} : one type-7 field", brace_group(two), ["field/t7"], False)

    # ---- $C3, the pane count ---------------------------------------------
    print("panes -- byte[1] of a token is the pane it belongs to ($8279/$8DB2):")
    for want, toks, what in (
            (0x81, text_token("A"), "one pane -> $C3 = 1 | $80 (◀▶ inert)"),
            (0x02, text_token("A") + text_token("B", row=14, cond=PANE(2)),
             "two panes -> $C3 = 2"),
            (0x03, text_token("A") + text_token("B", row=14, cond=PANE(2))
             + text_token("C", row=16, cond=PANE(3)), "three panes -> $C3 = 3"),
            (0x81, text_token("A") + text_token("B", row=14, cond=PANE_ALWAYS),
             "PANE_ALWAYS does not raise the count")):
        m = card.measure(build_content(toks))
        good = m["error"] is None and m["c3"] == want and m["b8"] == 1
        if not good:
            ok = False
        print("  %s %-46s $C3 = $%02X, $B8 = $%02X %s"
              % ("ok " if good else "FAIL", what, m["c3"], m["b8"],
                 m["error"] or ""))
    for bad, why in ((0, "pane 0"), (0x20, "pane 32")):
        try:
            text_token("A", cond=bad)
        except ValueError:
            print("  ok  the builder refuses %s" % why)
        else:
            ok = False
            print("  FAIL: %s must be refused" % why)

    # ---- a long page: how far the table grows, and what the form submits ---
    print("a long list -- 40 rows over 5 panes ($96B6 -> $9BC7 -> $98A8):")
    LONG, PER_PANE = 40, 9
    long_rows = [text_token("ROW %02d" % (i + 1), col=4,
                            row=6 + (i % PER_PANE) * 2, width=12,
                            cond=PANE(i // PER_PANE + 1)) for i in range(LONG)]
    long_page = build_content(group(long_rows, b1=0x90), b1=0x91, extra=b"\x83")
    m = card.measure(long_page)
    want_end = FIELD_TABLE + LONG * 6
    good = (m["error"] is None and len(m["fields"]) == LONG
            and m["table_end"] == want_end)
    if not good:
        ok = False
    print("  %s %d field(s), table $%04X..$%04X, %d B  %s"
          % ("ok " if good else "FAIL", len(m["fields"]), FIELD_TABLE,
             m["table_end"], m["table_end"] - FIELD_TABLE, m["error"] or ""))
    before = card.read_range(FIELD_TABLE, want_end - FIELD_TABLE)
    r = card.reachable(long_page)
    good = (r["error"] is None and r["panes"] == 5
            and sorted(r["payloads"]) == [b"0%02d" % (i + 1)
                                          for i in range(LONG)])
    if not good:
        ok = False
    print("  %s every row reachable over %d pane(s), each submitting its own "
          "index  %s" % ("ok " if good else "FAIL", r["panes"],
                         r["error"] or ""))
    if card.read_range(FIELD_TABLE, want_end - FIELD_TABLE) != before:
        ok = False
        print("  FAIL: the cursor walk moved the field table under itself")
    else:
        print("  ok  the walk leaves the table byte-identical")

    for m, what in ((flat, "flat"), (armed, "armed")):
        f = m["fields"][0]
        if (f["type"], f["count"], f["selected"]) != (5, 3, 1):
            ok = False
            print("  FAIL: the %s cycler must read back type 5, count 3, "
                  "selected 1 -- got %s" % (what, f["raw"].hex(" ")))
        else:
            print("  ok  the %s cycler: type 5, count 3, selected 1, token $%04X"
                  % (what, f["token"]))
    if armed["fields"][0]["raw"][3] & 0x80 == 0:
        ok = False
        print("  FAIL: $8317 must set byte[3] bit 7 once $BD is 1")

    # ---- the canonical header, $FAE1 -------------------------------------
    print("the canonical header ($FAE1 scatters every lead into $718F):")
    WANT_MAPS = {
        0xC0: [0, 1, None, 2, 3, 4, 5, None, 6, 7, None, None, 8, None],
        0x80: [0, None, None, 1, 2, 3, 4, None, 5, 6, None, None, 7, None],
        0xA0: [0, None, None, None, 1, 2, 3, 4, 5, None, None, None, None, None],
        0xC1: [0, None, 1, 2, 3, 4, 5, None, 6, 7, 8, None, 9, 10],
        0x81: [0, None, None, 1, 2, 3, 4, None, 5, 6, 7, None, 8, 9],
    }
    for lead, want in WANT_MAPS.items():
        got = card.header_map(lead)
        good = got == want
        if not good:
            ok = False
        print("  %s $%02X header %2d bytes  %s"
              % ("ok " if good else "FAIL", lead,
                 max(b for b in (got or [0]) if b is not None) + 1,
                 " ".join("--" if b is None else "%2d" % b for b in (got or []))))
    for lead in (0x82, 0x95):
        if card.header_map(lead) is not None:
            ok = False
            print("  FAIL: $%02X must have no map -- its renderer reads the "
                  "token directly" % lead)
        else:
            print("  ok  $%02X has no map" % lead)

    # bank 5 $BB23, the on-screen keyboard: the ground truth for a $80 header.
    got = card.header(bytes.fromhex("80 81 85 8c d7 84 80 80"))
    want = bytes.fromhex("80 00 00 81 85 8c d7 00 84 80 00 00 80 00")
    if got != want:
        ok = False
        print("  FAIL: $BB23 normalizes to %s, want %s"
              % (got.hex(" "), want.hex(" ")))
    else:
        print("  ok  $BB23 -> col $85 row $8C width $D7 style $84 fill $80")

    # ---- the $A0 paragraph token -----------------------------------------
    print("the $A0 paragraph token ($8995 measures it by rendering it):")
    para = para_token("ABCDE", col=4, row=5, width=20, height=8)
    if len(para) != 6 + 5 + 2:
        ok = False
        print("  FAIL: a $A0 is 6 header bytes + text + $5C $FE")
    stream("a paragraph token $A0", para)
    stream("a paragraph beside a text token", para + text_token("A"))
    # 40 characters wrapped at 10 is four lines: one pane at height 8, two at 2.
    for h, want, what in ((8, 0x81, "fits in its height: one pane"),
                          (2, 0x02, "overflows: $AF spills onto a second")):
        m = card.measure(build_content(
            para_token("A" * 40, col=4, row=5, width=10, height=h)))
        good = m["error"] is None and m["c3"] == want
        if not good:
            ok = False
        print("  %s height %-2d %-42s $C3 = $%02X %s"
              % ("ok " if good else "FAIL", h, what, m["c3"], m["error"] or ""))
    # ---- wrapped(): the word wrap the card does not do -------------------
    print("wrapped() -- $5C $F0 at word boundaries, cells counted as $AF1C does:")
    WRAPS = (
        ("plain prose", "WELCOME TO MARIO CLUB. THIS PARAGRAPH TESTS WORD "
                        "WRAP AND PAGE TURNS.", 23,
         ["WELCOME TO MARIO CLUB.", "THIS PARAGRAPH TESTS",
          "WORD WRAP AND PAGE", "TURNS."]),
        # ﾌﾞ and ﾍﾟ are two bytes each and must not be split from their marks.
        ("kana with voiced marks", "ﾌﾞﾝｼｮｳ ﾊ ﾍﾟｰｼﾞ ｵｸﾘ", 12,
         ["ﾌﾞﾝｼｮｳ ﾊ", "ﾍﾟｰｼﾞ ｵｸﾘ"]),
        ("a word longer than the width", "AB SUPERCALIFRAGILISTIC", 10,
         ["AB", "SUPERCALIF", "RAGILISTIC"]),
        ("a break the caller placed", "ONE\nTWO THREE", 20, ["ONE", "TWO THREE"]),
    )
    for what, src, width, want in WRAPS:
        got = wrapped(src, width)
        lines = got[:-2].split(b"\x5c\xf0")
        good = (got.endswith(b"\x5c\xfe")
                and lines == [halfwidth(w, terminate=False) for w in want]
                and all(len(ln) <= width for ln in lines))
        if not good:
            ok = False
        print("  %s %-30s %d line(s) <= %d cells  %s"
              % ("ok " if good else "FAIL", what, len(lines), width,
                 "" if good else [ln.hex(" ") for ln in lines]))
    # An escape is free: $5C $3C / $5C $3E move $CF and draw nothing, so a line
    # carrying them still fits.  $5C $5C is the one that costs a cell.
    emph = wrapped(b"AAA \x5c\x3cBBB\x5c\x3e CCC", 8)
    if emph[:-2].split(b"\x5c\xf0") != [b"AAA \x5c\x3cBBB\x5c\x3e", b"CCC"]:
        ok = False
        print("  FAIL: $5C escapes must not count against the width -- got %s"
              % emph.hex(" "))
    else:
        print("  ok  $5C $3C / $5C $3E cost no cells")
    # ...and the ROM agrees the result is a legal token.
    r = card.check_content(build_content(
        para_token("ONE TWO THREE FOUR FIVE SIX", col=4, row=5,
                   width=10, height=4, wrap=True)))
    if r["error"] is not None:
        ok = False
        print("  FAIL: a wrapped paragraph must still parse -- %s" % r["error"])
    else:
        print("  ok  para_token(wrap=True) walks clean through $88D0")

    # ---- the card's own glyphs --------------------------------------------
    print("the card's own glyphs (bank 7 $CE8D and $CEAD):")
    for what, got, want in (
            ("a card tile is one byte, one cell", halfwidth("✌", False), b"\x02"),
            ("a full-width pair is two cells",
             (halfwidth("◆", False), cells("◆")), (b"\x81\x9f", 2)),
            ("{NAME} names a glyph", halfwidth("{IV}", False), b"\x85\x49"),
            ("an unknown {NAME} stays text",
             halfwidth("{x}", False), b"{x}"),
            ("clip() never splits a pair", clip("A◆B", 2, False), b"A"),
            ("clip() keeps a whole pair", clip("A◆B", 3, False), b"A\x81\x9f")):
        if got != want:
            ok = False
        print("  %s %-36s %s" % ("ok " if got == want else "FAIL", what,
                                 "" if got == want else f"got {got!r}"))
    bad = [ch for ch in {**CARDTILE, **FULLWIDTH}
           if card.check_content(build_content(
               text_token("A" + ch, col=4, row=6, width=8,
                          style=STYLE_PLAIN)))["error"]]
    if bad:
        ok = False
    print("  %s every glyph parses in a STYLE_PLAIN token%s"
          % ("ok " if not bad else "FAIL", "" if not bad else f" -- {bad}"))
    try:
        text_token("A◆", style=STYLE_NARROW)
        ok = False
        print("  FAIL: a narrow token must refuse a full-width pair")
    except ValueError:
        print("  ok  a narrow token refuses a full-width pair")

    # ---- the type-2 field -------------------------------------------------
    print("the type-2 field ($C0 / $C1, registered by $824D -> $85C4):")
    for what, tok, want_len in (
            ("$C0 blank, 8 wide", input_token(8, col=12, row=12), 9 + 8),
            ("$C0 with a value", input_token(6, col=12, row=12,
                                             value="ABC   "), 9 + 6),
            ("$C0 direct entry ($20)", input_token(8, col=12, row=12,
                                                   options=FIELD_DIRECT), 9 + 8),
            ("$C1 four digits + two", number_token(4, 2, col=12, row=16),
             11 + 6),
            ("$C1 blank fill ($20)", number_token(6, col=12, row=16,
                                                  options=FIELD_DIRECT),
             11 + 6)):
        blk = build_content(tok)
        r, m = card.check_content(blk), card.measure(blk)
        f = m["fields"][0] if m["fields"] else {}
        good = (len(tok) == want_len and r["error"] is None
                and m["error"] is None and f.get("type") == 2
                and r["walk"]["tokens"] == [(0, tok[0], len(tok))])
        if not good:
            ok = False
        print("  %s %-24s %2dB  type=%s  $B9=$%02X  %s"
              % ("ok " if good else "FAIL", what, len(tok), f.get("type"),
                 m["b9"], r["error"] or m["error"] or ""))

    # Two fields on separate rows: $71BA can reach both.  On one row it would
    # be a single reachable field, which is a page bug, not a builder
    # one -- so this only checks that the table really holds two.
    two = card.measure(build_content(
        input_token(6, col=12, row=12) + number_token(4, col=12, row=16)))
    if [f.get("type") for f in two["fields"]] != [2, 2]:
        ok = False
        print("  FAIL: two type-2 fields must register two descriptors -- got "
              "%s" % [f.get("type") for f in two["fields"]])
    else:
        print("  ok  two on separate rows -> two descriptors, $B9 = $%02X"
              % two["b9"])

    for call, why in ((lambda: input_token(8, value=b"x" * 31),
                       "a $C0 value of 31 bytes"),
                      (lambda: input_token(8, value=b"a\x03b"),
                       "$03 inside a value"),
                      (lambda: number_token(30, 5), "35 digits in a $C1"),
                      (lambda: number_token(4, 2, value=b"123"),
                       "a $C1 value that is not `integer + decimals` long"),
                      (lambda: input_token(8, cond=0), "pane 0")):
        try:
            call()
        except ValueError:
            print("  ok  the builder refuses %s" % why)
        else:
            ok = False
            print("  FAIL: %s must be refused" % why)

    for kw, why in (({"text": b"AB"}, "text with no $5C $FE"),
                    ({"width": 32}, "a width of 32"),
                    ({"height": 0}, "a height of 0")):
        try:
            para_token(**{"text": "A", **kw})
        except ValueError:
            print("  ok  the builder refuses %s" % why)
        else:
            ok = False
            print("  FAIL: %s must be refused" % why)

    print("SELF-TEST", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def _many_entries(n):
    body = b"".join(b"\x81\x7f\x81\x7f*" for _ in range(n))
    return body + b"/" * 4 + b"\x03"


def _many_items(n):
    return b"\x81\x7f" + b"\x81\x7f" * n + b"/" * 4 + b"\x03"


def _many_f3(n):
    """`n` field-3 items spread over as many entries as it takes."""
    f1, f3 = bytearray(), bytearray()
    left = n
    while left:
        k = min(MAX_ITEMS, left)
        f1 += b"\x81\x7f" + b"\x80\x7f" * k + b"*"
        f3 += b"z" * (FIELD3_LEN * k)
        left -= k
    f1[-1] = SLASH
    return bytes(f1) + b"/" + bytes(f3) + b"//\x03"


# ---------------------------------------------------------------- reporting

def _sjis(bs):
    out, i = [], 0
    while i < len(bs):
        b = bs[i]
        if (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEF) and i + 1 < len(bs):
            pair = bs[i:i + 2]
            try:
                out.append(pair.decode("shift_jis"))
            except UnicodeDecodeError:
                out.append("<%s>" % pair.hex())
            i += 2
        else:
            out.append(chr(b) if 0x20 <= b < 0x7F else "<%02x>" % b)
            i += 1
    return "".join(out)


def _names(card):
    print("built-in name table -- bank %d $%04X, %d bytes each ($F490)"
          % (NAME_TABLE_BANK, NAME_TABLE_ADDR, NAME_LEN))
    for i, n in enumerate(card.names()):
        blank = n == b" " * NAME_LEN
        print("  $%02X  %s  %s" % (0x81 + i, n.hex(" "),
                                   "(blank)" if blank else "|%s|" % _sjis(n)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rom", default=None,
                    help="a ROM image to run the card's own code against; "
                         "$SMC_ROM or roms/smc.nes when unset.  Only --names "
                         "and --form require one")
    ap.add_argument("--selftest", action="store_true",
                    help="check every derived rule, against the real parser "
                         "too when a ROM image is available")
    ap.add_argument("--names", action="store_true",
                    help="print the card's built-in 16-byte name table")
    ap.add_argument("--demo", action="store_true",
                    help="build a menu from the built-in names and verify it")
    ap.add_argument("--parse", metavar="HEX",
                    help="run the parser over a record given as hex")
    ap.add_argument("--form", metavar="HEX",
                    help="drive a content block's widgets: every row the "
                         "cursor reaches, and what EXECUTE submits there")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()

    card = checker(args.rom)
    if (args.names or args.form) and not card.modeled:
        print("--names and --form run the card's own code, so they need a ROM "
              "image: set $SMC_ROM to a dump of your own cartridge.",
              file=sys.stderr)
        return 2
    if args.names:
        _names(card)
        return 0

    if args.parse:
        rec = bytes.fromhex(args.parse.replace(",", " "))
        res = card.parse(rec)
        print("record (%d bytes): %s" % (len(rec), rec.hex(" ")))
        if res["error"]:
            print("-> error %s" % res["error"])
            return 1
        print("-> ok, %d entries" % res["entries"])
        for i in range(res["entries"]):
            line = res["buffers"]["lines"][i * 22:(i + 1) * 22]
            print("   %2d |%s|" % (i, _sjis(line)))
        return 0

    if args.form:
        blk = bytes.fromhex(args.form.replace(",", " "))
        m = card.measure(blk)
        print("%d field(s), table $%04X..$%04X"
              % (len(m["fields"]), FIELD_TABLE, m["table_end"]))
        r = card.reachable(blk)
        if r["error"]:
            print("-> error %s" % r["error"])
            return 1
        print("%d pane(s), %d reachable row(s)" % (r["panes"], len(r["rows"])))
        for pane, row, pay in r["rows"]:
            print("   pane %d row %2d -> %s"
                  % (pane, row, pay.decode("ascii", "replace") if pay else "-"))
        return 0

    if args.demo:
        entries = [{"name": 0x81 + i, "items": [(0x81 + i, 0x7F)]}
                   for i in range(10)]
        rec = build_record(entries)
        res = card.parse(rec)
        print("record (%d bytes): %s" % (len(rec), rec.hex(" ")))
        print("-> %s, %s entries" % (res["error"] or "ok", res["entries"]))
        if res["error"] is None:
            for i in range(res["entries"]):
                line = res["buffers"]["lines"][i * 22:(i + 1) * 22]
                print("   %2d |%s|" % (i, _sjis(line)))
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
