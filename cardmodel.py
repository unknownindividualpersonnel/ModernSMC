#!/usr/bin/env python3
"""The card's acceptance checks, in Python -- no ROM image, no emulator.

Every rule here was read off the card's own code and then differential-tested
against it: `python3 content.py --selftest` runs this model and the real
`$AC67` / `$87AF` / `$88D0` side by side whenever a ROM image is available, and
fails if the two ever disagree.  Nothing in the serving path needs the ROM.

What is modeled: the record grammar and its thirteen error codes, the trailer
header, and the content-stream token walk.  What is NOT is the measure pass
(`$80B7`) and the cursor walk -- widget geometry needs the machine itself, so
`measure()` and `reachable()` report `modeled=False` rather than a guess.
"""

# $881D's verdict for every lead byte, enumerated from the card.
STREAM_LEADS = (0x28, 0x3C, 0x7B, 0x80, 0x81, 0x82,
                0x95, 0x96, 0x9A, 0xA0, 0xC0, 0xC1)

# lead -> (offset of the length byte, mask).  Advance is offset + (byte & mask).
STREAM_LENGTH = {0x81: (8, 0x1F), 0x82: (7, 0x7F),
                 0xC0: (8, 0x7F), 0xC1: (9, 0x1F)}

# $80 carries a length at byte[7], but a zero there means "measure the text",
# and $A0 has no length byte at all.  Both bodies end $5C $FE.
STREAM_MEASURED = {0x80: (8, 7, 0x7F), 0xA0: (6, None, None)}

# Accepted by $881D, but their handlers need machine state; never built here.
STREAM_UNMODELED = (0x95, 0x96, 0x9A)

BRACKETS = {0x28: 0x29, 0x3C: 0x3E, 0x7B: 0x7D}
GROUP_SEP = 0x3B

# Field-4 pages are a different token layer from the bank-5 stream.
FIELD4_LENGTH = {0x80: (7, 0x7F), 0xC1: (9, 0x1F)}

SLASH, STAR, ETX, EOT = 0x2F, 0x2A, 0x03, 0x04
ESC, ESC_END = 0x5C, 0xFE
NAME_LEN, FIELD3_LEN = 16, 25
MAX_ENTRIES, MAX_ITEMS, MAX_FIELD3 = 16, 8, 55
LINE_LEN = 22               # 6 spaces + the 16-byte name
BUILD_TOP = 0x8000 - 0x7AA0  # room for field-4 pages before $AC67 overruns


class Reject(Exception):
    """A four-digit code the card would display."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def group_header(b1):
    """$8833: 3 for $91, 2 for $8n / $90 / $An / $B0, else 4981."""
    if 0x80 <= b1 <= 0x8F or 0xA0 <= b1 <= 0xAF or b1 in (0x90, 0xB0):
        return 2
    if b1 == 0x91:
        return 3
    raise Reject("4981")


def is_sjis_lead(b):
    """$B6FA: high nibble $8/$9, or $E0-$EB, takes a second byte with it."""
    return (b >> 4) in (0x8, 0x9) or 0xE0 <= b <= 0xEB


def _scan_escaped(block, at):
    """End of a $5C $FE terminated body, one past the marker."""
    i = at
    while i < len(block):
        b = block[i]
        if b == ESC:
            if i + 1 >= len(block):
                return None
            if block[i + 1] == ESC_END:
                return i + 2
            i += 2                      # $5C $5C, $5C $F0, $5C nn
        elif is_sjis_lead(b):
            i += 2                      # a pair is never split, $5C included
        else:
            i += 1
    return None


class CardModel:
    """Stands in for content.Card when no ROM image is present."""

    modeled = False          # measure()/reachable() are not

    # ---- the content stream ----------------------------------------------
    def check_token(self, lead):
        if lead in STREAM_LEADS:
            return None
        return "4980" if lead < 0x80 else "4988"

    def _advance(self, block, at):
        """How many bytes the token at `at` occupies, or a Reject."""
        lead = block[at]
        bad = self.check_token(lead)
        if bad is not None:
            raise Reject(bad)
        if lead in STREAM_UNMODELED:
            raise Reject("$%02X has no modeled length -- run with a ROM image"
                         % lead)
        if lead in BRACKETS:
            return self._bracket(block, at)
        if lead in STREAM_LENGTH:
            off, mask = STREAM_LENGTH[lead]
            if at + off >= len(block):
                raise Reject("4980")        # the length byte is past the end
            return off + (block[at + off] & mask)
        head, off, mask = STREAM_MEASURED[lead]
        if off is not None:
            if at + off >= len(block):
                raise Reject("4980")
            n = block[at + off] & mask
            if n:
                return off + n
        end = _scan_escaped(block, at + head)
        if end is None:
            raise Reject("4980")            # no $5C $FE before the end
        return end - at

    def _bracket(self, block, at):
        lead = block[at]
        if lead == 0x28 and at + 1 >= len(block):
            raise Reject("4981")
        head = group_header(block[at + 1]) if lead == 0x28 else 1
        if at + head >= len(block):
            raise Reject("4980")
        close, i = BRACKETS[lead], at + head
        first = True
        while i < len(block):
            b = block[i]
            if first and b < 0x80:
                raise Reject("4987")        # $880C: a bracket's first child
            if b == close:
                return i + 1 - at
            if b == GROUP_SEP:
                i += 1
                first = True
                continue
            i += self._advance(block, i)
            first = False
        raise Reject("4980")                # unterminated bracket

    def walk_stream(self, block, addr=None):
        out = {"tokens": [], "ends_at": None, "clean": False, "error": None}
        off = 0
        while off < len(block):
            try:
                n = self._advance(block, off)
            except Reject as r:
                out["error"] = r.code
                out["ends_at"] = off
                return out
            out["tokens"].append((off, block[off], n))
            off += n
        out["ends_at"] = off
        out["clean"] = off == len(block)
        return out

    # ---- the trailer header ----------------------------------------------
    def check_trailer(self, block):
        """$87AF over the header that follows the record terminator."""
        if len(block) < 2:
            return "4970"
        b0, b1 = block[0], block[1]
        if b0 >> 4 not in (0x8, 0x9, 0xA):
            return "4970"
        if b0 >> 4 in (0x8, 0x9) and (b0 & 0x0F) >= 4:
            return "4970"
        if b1 >> 4 not in (0x8, 0x9, 0xA):
            return "4971"
        if b1 >> 4 == 0x8:
            return None
        n = b1 & 0x0F
        if n >= 10:
            return "4971"
        if len(block) < 2 + n:
            return "4972"
        if any(not 0x80 <= b <= 0x89 for b in block[2:2 + n]):
            return "4972"
        return None

    def check_content(self, block):
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

    # ---- the record ------------------------------------------------------
    def parse(self, record, addr=None):
        try:
            return self._parse(record)
        except Reject as r:
            return {"error": r.code, "entries": None, "buffers": None}

    def _parse(self, rec):
        # $ACDD scans FIELD 4 for the terminator, so an $03/$04 earlier in the
        # record is ordinary data -- a name or a field-3 byte.
        body = rec
        entries, names, sels, pages_wanted = [], 0, 0, 0
        p = 0

        while True:
            if p >= len(body):
                raise Reject("4940")
            name = body[p]
            p += 1
            if name < 0x80:
                raise Reject("4940")
            if name == 0x80:
                names += 1
            if p >= len(body):
                raise Reject("4941")
            action = body[p]
            p += 1
            if action < 0x7F:
                raise Reject("4941")
            if action == 0x80:
                pages_wanted += 1
            items = []
            while True:
                if p >= len(body):
                    raise Reject("4942")
                sel = body[p]
                if sel in (STAR, SLASH):
                    break
                p += 1
                if sel < 0x80:
                    raise Reject("4942")
                if sel == 0x80:
                    sels += 1
                    if sels > MAX_FIELD3:
                        raise Reject("494C")
                if p >= len(body):
                    raise Reject("4943")
                param = body[p]
                p += 1
                if param < 0x7F:
                    raise Reject("4943")
                items.append((sel, param))
                if len(items) > MAX_ITEMS:
                    raise Reject("494B")
            if not items:
                raise Reject("4945")
            entries.append({"name": name, "action": action, "items": items})
            if len(entries) > MAX_ENTRIES:
                raise Reject("494A")
            term = body[p]
            p += 1
            if term == SLASH:
                break

        f2, p = p, p + names * NAME_LEN
        # A separator inside a name moves the card's own field boundary and the
        # record parses as something else entirely -- refuse it here instead.
        if any(b in (SLASH, STAR, ETX, EOT) for b in body[f2:p]):
            raise Reject("4946")
        if p >= len(body) or body[p] != SLASH:
            raise Reject("4946")
        p += 1
        f3, p = p, p + sels * FIELD3_LEN
        if any(b in (SLASH, STAR, ETX, EOT) for b in body[f3:p]):
            raise Reject("4947")
        if p >= len(body) or body[p] != SLASH:
            raise Reject("4947")
        p += 1
        end = next((i for i in range(p, len(body)) if body[i] in (ETX, EOT)),
                   None)
        if end is None:
            raise Reject("4949")            # $ACDD never finds a terminator
        pages = self._field4(body[:end], p, pages_wanted)

        return {"error": None, "entries": len(entries),
                "buffers": self._buffers(entries, body, f2, f3, pages)}

    def _field4(self, body, p, wanted):
        """One token-stream page per $80 action, $STAR between, $SLASH last."""
        pages = []
        for n in range(wanted):
            start = p
            while True:
                if p >= len(body):
                    raise Reject("4949")    # the page ran past the terminator
                b = body[p]
                if b in (STAR, SLASH):
                    break
                p += self._field4_advance(body, p)
            pages.append(bytes(body[start:p]))
            # '*' between pages, '/' after the last one -- never the other way.
            if (body[p] == SLASH) != (n == wanted - 1):
                raise Reject("4948")
            p += 1
        if wanted == 0:
            if p >= len(body) or body[p] != SLASH:
                raise Reject("4948")
            p += 1
        if p != len(body):
            raise Reject("4948")
        if sum(len(x) + 1 for x in pages) > BUILD_TOP:
            raise Reject("494C")
        return pages

    def _field4_advance(self, body, at):
        lead = body[at]
        if lead == 0x28:
            return self._bracket(body, at)
        if lead not in FIELD4_LENGTH:
            raise Reject("4948")
        off, mask = FIELD4_LENGTH[lead]
        if at + off >= len(body):
            raise Reject("4949")
        return off + (body[at + off] & mask)

    def _buffers(self, entries, body, f2, f3, pages):
        """$AC67's build buffers, as far as they can be known without the ROM."""
        lines, inline, items, counts, action = b"", 0, b"", b"", b""
        ordinal = {"page": 0, "record": 0}
        for e in entries:
            if e["name"] == 0x80:
                name = bytes(body[f2 + inline * NAME_LEN:
                                  f2 + (inline + 1) * NAME_LEN])
                inline += 1
            else:
                # The ROM name table is in the card, not here.
                name = ("$%02X" % e["name"]).ljust(NAME_LEN).encode("ascii")
            lines += b"      " + name
            counts += bytes([len(e["items"])])
            if e["action"] == 0x80:                 # $051E, the page ordinal
                action += bytes([ordinal["page"]])
                ordinal["page"] += 1
            else:
                action += bytes([e["action"]])
            row = b""
            for sel, param in e["items"]:
                if sel == 0x80:                     # $051F, the record ordinal
                    row += bytes([ordinal["record"], param])
                    ordinal["record"] += 1
                else:
                    row += bytes([sel, param])
            items += row.ljust(NAME_LEN, b"\x00")
        return {"action": action, "counts": counts, "items": items,
                "lines": lines, "pages": pages}

    # ---- what only the machine can answer --------------------------------
    def measure(self, block, **kw):
        return {"error": None, "fields": None, "interactive": None,
                "modeled": False, "table_end": None,
                "b8": None, "b9": None, "ba": None, "c3": None}

    def reachable(self, block, **kw):
        return {"error": None, "panes": None, "rows": [], "payloads": None,
                "modeled": False}

    def names(self, count=16):
        return None

    def page_titles(self, count=34):
        return None
