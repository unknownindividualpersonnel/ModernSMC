#!/usr/bin/env python3
"""The message text carried in an SMC server reply — encoder and layout engine.

The login reply's data field is not opaque.  Bank 6 `$86AC` hands its bytes
from `$610B` to the routine at `$B60D`, which is a WORD-WRAP ENGINE: it lays
Shift-JIS text into fixed screen rows and emits a `$D787` screen-drawing record
at `$7600`.  The card's `$D787` screen records are built at runtime, not held
as static blocks; this is one of the things that builds them, out of bytes off
the wire.

    $86AC: JSR $B60D / .byte 0B 61 00 76 60 00
                             ^^^^^ ^^^^^ ^^^^^
                             src   dest  bound
                             $610B $7600 $0060

ROW TABLE -- `$B600`, three bytes per row, `$FF`-terminated:

    04 0C 18   column 4, row 12, 24 characters
    04 0F 18   column 4, row 15, 24 characters
    04 12 18   column 4, row 18, 24 characters
    04 15 18   column 4, row 21, 24 characters
    FF

Four rows x 24 = 96 = exactly the `$0060` bound, so the bound is "one screenful".

THE WIRE FORMAT ($B6FA, $B75C/$B763, $B7D5)

  * Text is Shift-JIS.  A byte whose high nibble is `$80`/`$90`, or `$Ex` with
    low nibble < `$0C`, is a double-byte LEAD byte and is laid out with width 0
    so the pair can never be split across a row boundary.  Everything else is
    one column wide.
  * `$5C` (backslash / yen) is the escape introducer.  The byte after it:

        $FE   END OF MESSAGE   -- sets $7507, which is what stops $B60D's loop
        $F0   new row
        $FF   new page (also new row; wraps the row table)
        $5C   a literal $5C
        else  (n & $1F) spaces, n == 0 does nothing

  * Wrapping is automatic at the row width; the row's length byte in the
    emitted record is patched to the real count as each row closes.
  * `$B695` stops the whole thing once `$7500` reaches 2, i.e. after two pages.

Running out of source without a `\\$FE` is NOT a fault -- `$B67C` compares the
source pointer against the bound and exits, then `$B8A6` closes the record.  So
'0' padding in a reply is merely ugly (24 zeros drawn on screen), not dangerous.

    python3 message.py --selftest
    python3 message.py --text 'こんにちは'
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# From bank 6, $B600.  verify_rows() re-reads it from a ROM image so this can
# never silently drift from the ROM.
ROWS = [(0x04, 0x0C, 0x18), (0x04, 0x0F, 0x18),
        (0x04, 0x12, 0x18), (0x04, 0x15, 0x18)]
ROW_TABLE_ADDR = 0xB600
BOUND = 0x60            # the inline argument at $86AC
MAX_PAGES = 2           # $B695: LDA $7500 / CMP #$02 / BCS exit

ESC = 0x5C
END = bytes([ESC, 0xFE])
NEWROW = bytes([ESC, 0xF0])
NEWPAGE = bytes([ESC, 0xFF])
LITERAL_ESC = bytes([ESC, ESC])


def spaces(n: int) -> bytes:
    """`\\` + n -> n spaces.  Only the low five bits are used ($B892)."""
    if not 0 <= n <= 0x1F:
        raise ValueError("space runs are 0..31 ($B892 masks with $1F)")
    return bytes([ESC, n])


def is_lead(b: int) -> bool:
    """$B724's test for a double-byte lead byte."""
    hi = b & 0xF0
    return hi in (0x80, 0x90) or (hi == 0xE0 and (b & 0x0F) < 0x0C)


def encode(text: str, terminate: bool = True) -> bytes:
    """Shift-JIS encode a string, with `\\` doubled, and terminate it."""
    out = bytearray()
    for ch in text:
        if ch == "\n":
            out += NEWROW
            continue
        b = ch.encode("cp932")
        if b == b"\x5c":
            out += LITERAL_ESC
        else:
            out += b
    if terminate:
        out += END
    return bytes(out)


class Layout:
    """A transcription of $B60D's loop and the routines it drives.

    Emits the same `$D787` record the card would build at $7600, so a message
    can be checked offline: does it terminate, how many rows does it use, and
    what ends up drawn.
    """

    def __init__(self, rows=None, bound: int = BOUND):
        self.rows = rows or ROWS
        self.bound = bound
        self.out = bytearray()      # the record built at $7600
        self.page = 1               # $7500
        self.row = 1                # $7501
        self.col = 1                # $7502
        self.pending_lead = False   # $7503
        self.pending_esc = False    # $7504
        self.suppress = False       # $7506
        self.done = False           # $7507
        self.len_at = None          # $F4, index of the row's length byte
        self.reason = None
        self.consumed = 0

    # --- $B6B8: emit the next row's three-byte header -----------------------
    def _row_header(self):
        col, row, ln = self.rows[self.row - 1]
        self.out += bytes([col, row, ln])
        self.len_at = len(self.out) - 1

    def _emit(self, b: int):        # $B7C7
        self.out.append(b)

    def _row_len(self):             # ($F4) -- the current row's width limit
        return self.out[self.len_at]

    # --- $B75C (width 1) / $B763 (width 0, a lead byte) --------------------
    def _put(self, b: int, width: int):
        self.suppress = False
        if self.col < self._row_len() + width:
            self._emit(b)
            self.col += 1
            return
        # wrap: patch this row's length, move to the next row
        self.out[self.len_at] = self.col - 1
        self.col = 1
        self.row += 1
        if self.row > len(self.rows):          # ($F2),Y == $FF
            self.row = 1
            self.page += 1
            self.suppress = True
            self._emit(0xFF)                   # close the page
        self._row_header()
        self._emit(b)
        self.col += 1

    def _close_row(self):
        """The `$7502 == 1 -> un-emit the header` idiom at $B7E3 / $B825."""
        if self.col == 1:
            del self.out[len(self.out) - 3:]
        else:
            self.out[self.len_at] = self.col - 1

    # --- $B7D5: the byte after an escape -----------------------------------
    def _escape(self, b: int):
        if b == 0xFF:                                   # new page
            if not self.suppress:
                self._close_row()
                self._emit(0xFF)
                self.page += 1
                self.row = 1
                self.col = 1
                self._row_header()
            self.suppress = False
        elif b == 0xF0:                                 # new row
            self.suppress = False
            self._close_row()
            self.row += 1
            self.col = 1
            if self.row > len(self.rows):
                self.page += 1
                self.row = 1
                self.suppress = True
                self._emit(0xFF)
            self._row_header()
        elif b == 0xFE:                                 # END
            self.done = True
        elif b == ESC:
            self._put(ESC, 1)
        else:
            for _ in range(b & 0x1F):
                self._put(0x20, 1)

    # --- $B6FA: one source byte -------------------------------------------
    def _byte(self, b: int):
        if self.pending_lead:                # second half of a double-byte char
            self.pending_lead = self.pending_esc = False
            self._put(b, 1)
        elif self.pending_esc:
            self.pending_esc = False
            self._escape(b)
        elif is_lead(b):
            self.pending_lead = True
            self._put(b, 0)
        elif b == ESC:
            self.pending_esc = True
        else:
            self._put(b, 1)

    # --- $B60D's loop ------------------------------------------------------
    def run(self, src: bytes):
        self._row_header()
        for i, b in enumerate(src[:self.bound]):
            self.consumed = i + 1
            self._byte(b)
            if self.done:
                self.reason = "end marker"
                break
            if self.page >= MAX_PAGES:
                self.reason = "page limit ($7500 == 2)"
                break
        else:
            self.reason = ("source bound" if len(src) >= self.bound
                           else "source exhausted")
        self._finish()
        return bytes(self.out)

    # --- $B8A6: close the record ------------------------------------------
    def _finish(self):
        self.col -= 1
        if self.col:
            self.out[self.len_at] = self.col
        elif self.row > 1 or self.page > 1:
            del self.out[len(self.out) - 3:]
        else:
            self.out[self.len_at] = 1
            self._emit(0x20)
        self._emit(0xFF)


def layout(src: bytes, rows=None, bound: int = BOUND):
    """Run the engine; returns (record, info)."""
    e = Layout(rows, bound)
    rec = e.run(src)
    return rec, {"reason": e.reason, "terminated": e.done,
                 "consumed": e.consumed, "rows_used": e.row, "pages": e.page}


def describe(record: bytes) -> str:
    """Read back a $D787 record as `col,row: text` lines."""
    out, i = [], 0
    while i < len(record):
        if record[i] == 0xFF:
            out.append("-- end of page --")
            i += 1
            continue
        if i + 3 > len(record):
            out.append(f"!! truncated header {record[i:].hex(' ')}")
            break
        col, row, ln = record[i], record[i + 1], record[i + 2]
        body = record[i + 3:i + 3 + ln]
        try:
            text = body.decode("cp932")
        except UnicodeDecodeError:
            text = body.decode("cp932", "replace")
        out.append(f"col {col:2d} row {row:2d} len {ln:2d}: {text}")
        i += 3 + ln
    return "\n".join(out)


def verify_rows(rom_path: str = None):
    """Re-read the $B600 table so ROWS can never drift.  Needs a ROM image."""
    import content
    rom_path = rom_path or content.rom_path()
    if not rom_path:
        return None
    raw = open(rom_path, "rb").read()
    if raw[:4] == b"NES\x1a":
        raw = raw[16:]
    bank = raw[6 * 0x4000:7 * 0x4000]
    off = ROW_TABLE_ADDR - 0x8000
    rows = []
    while bank[off] != 0xFF:
        rows.append(tuple(bank[off:off + 3]))
        off += 3
    return rows


def _selftest() -> int:
    ok = True
    rows = verify_rows()
    if rows is None:
        print("row table: not cross-checked (no ROM image; set $SMC_ROM)")
    else:
        match = rows == ROWS
        print(f"row table: {rows}")
        print("rom match:", "PASS" if match else "FAIL")
        ok &= match

    # A short message terminates on its own marker and uses one row.
    rec, info = layout(encode("ようこそ"))
    print(f"\nshort    : {info}")
    print(describe(rec))
    short_ok = (info["terminated"] and info["reason"] == "end marker"
                and info["rows_used"] == 1 and rec[-1] == 0xFF
                and rec[:2] == bytes(ROWS[0][:2]) and rec[2] == 8)
    print("short    :", "PASS" if short_ok else "FAIL")
    ok &= short_ok

    # Wrapping: 30 single-byte characters must break after 24.
    rec, info = layout(encode("A" * 30))
    lens = [rec[2], rec[3 + rec[2] + 2]]
    print(f"\nwrap     : {info}  row lengths {lens}")
    wrap_ok = lens == [24, 6] and info["rows_used"] == 2
    print("wrap     :", "PASS" if wrap_ok else "FAIL")
    ok &= wrap_ok

    # A double-byte pair must not straddle the boundary: 23 halves then a
    # kanji leaves column 24 free but width-0 forces the pair to the next row.
    rec, _ = layout(encode("A" * 23 + "日" + "B"))
    pair_ok = rec[2] == 23
    print(f"\npair     : first row {rec[2]} columns (must be 23, not 24)")
    print("pair     :", "PASS" if pair_ok else "FAIL")
    ok &= pair_ok

    # Escapes.
    rec, info = layout(b"A" + spaces(3) + b"B" + NEWROW + b"C" + END)
    print(f"\nescapes  : {info}")
    print(describe(rec))
    esc_ok = rec[2] == 5 and info["rows_used"] == 2 and info["terminated"]
    print("escapes  :", "PASS" if esc_ok else "FAIL")
    ok &= esc_ok

    # Unterminated padding: the 24 '0's a bare reply carries today.  Must not
    # run away -- the engine stops on the source bound and closes the record.
    rec, info = layout(b"0" * 24)
    print(f"\npadding  : {info}")
    pad_ok = (not info["terminated"] and rec[-1] == 0xFF
              and info["reason"] == "source exhausted")
    print("padding  :", "PASS" if pad_ok else "FAIL")
    ok &= pad_ok

    print("\nselftest :", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--text", help="lay out a message and show what is drawn")
    ap.add_argument("--hex", help="lay out raw bytes given as hex")
    a = ap.parse_args()
    if a.selftest:
        return _selftest()
    src = None
    if a.text is not None:
        src = encode(a.text)
    elif a.hex is not None:
        src = bytes.fromhex(a.hex.replace(" ", ""))
    if src is None:
        ap.print_help()
        return 1
    rec, info = layout(src)
    print(f"source : {src.hex(' ')}")
    print(f"record : {rec.hex(' ')}")
    print(f"info   : {info}")
    print(describe(rec))
    return 0


if __name__ == "__main__":
    sys.exit(main())
