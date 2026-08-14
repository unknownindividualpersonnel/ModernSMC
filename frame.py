#!/usr/bin/env python3
"""SMC / FCNS application-layer frame codec.

Transcribed from the Super Mario Club PRG and verified against a recorded
session (testdata/polarity_dle300.farend.bin): the self-test at the bottom
reproduces the card's own checksum byte for byte.

Frame, as built by bank 6 $85D1 and sent by the bank 7 mailbox layer:

    <payload>              N ASCII bytes, buffer pre-filled with '0' ($30)
    <ck1> <ck2>            $F058, both bytes forced to bit 7 = 1
    $03                    ETX  ($F084)
    $0D                    CR   (bank 6 $85F0, when $6E20 == 0)

The payload buffer lives at $0604 in card RAM, its length in zero page $60,
and the transport ships it to CPU2 three bytes per $40D0/$40D1/$40D2 write with
$40D3 strobed alternately $3F / $BF (an alternating-bit sequence number).  CPU2
itself is a byte pipe once $51 == 2 -- it does NOT frame or checksum anything,
so everything here belongs to the 6502 side.

Why the checksum looked like no standard CRC: it is a plain 8-bit sum with the
carries counted separately, then both output bytes have bit 7 forced set so
they can never collide with the ASCII payload or the $03/$0D terminators.

The SERVER -> CARD direction is the mirror, and is implemented here too:
build_reply()/card_verify() reproduce the four checks the card runs on an
inbound block ($F145, $F185, $F18B, $EF6C, plus $EE8B on the multi-block
paths).  Replies built here are accepted by a real cartridge: a whole session
runs against this server on stock hardware.
"""
import sys


def checksum(payload: bytes) -> bytes:
    """The card's own algorithm, a literal transcription of $F058 (bank 7).

        $F05B: LDA #$00 / LDX #$00 / LDY $60
        $F063: CLC / ADC $0603,y      ; carry never propagates into the sum
        $F067: BCC / INX              ; it is counted in X instead
        $F06A: DEY / BNE $F063
        $F06F: ROL / STA $63
        $F072: TXA / ROL / ORA #$80   ; -> ck1
        $F07C: LDA $63 / SEC / ROR    ; -> ck2
    """
    a = 0          # running sum, 8-bit
    x = 0          # number of carries
    c = 0          # carry out of the most recent ADC
    for b in payload:
        t = a + b
        c = 1 if t > 0xFF else 0
        a = t & 0xFF
        if c:
            x = (x + 1) & 0xFF

    t = (a << 1) | c              # ROL A
    c2 = (t >> 8) & 1
    saved = t & 0xFF              # STA $63

    ck1 = (((x << 1) | c2) & 0xFF) | 0x80     # TXA / ROL / ORA #$80
    ck2 = (saved >> 1) | 0x80                 # LDA $63 / SEC / ROR
    return bytes([ck1, ck2])


# --- payload structure -------------------------------------------------------
#
# $F00F lays down a fixed 10-byte header at $0604, $EFF5 copies the data in
# after it from card WRAM ($6000+, length in $6E49), and $F006 sets the total
# length $60 = $6E49 + 10.  The literals come from the table at $F051-$F057
# ('1','0','0','0','0','4','0'), and the three digits in the middle are $E672's
# binary -> 3-decimal-digit conversion of the DATA length:
#
#     '1' '0' D D D '0' '0' '0' '4' '0' <data...>
#      ^^^^^^  ^^^^^ ^^^^^^^^^^^^^^^^^
#      const   len    const
#
# Verified: the 2026-08-08 capture is "10" + "027" + "000" + "4" + "0" followed
# by exactly 27 data bytes, total 37 = the observed payload length.
#
# The "000", "4" and "0" are CONSTANTS ON THIS CODE PATH ONLY.  Other paths may
# use a different table; do not assume they are universal until one is seen.

HDR_LEN = 10

# Header offsets, named from what the card actually READS on an inbound block.
# The card only ever WRITES '4' and '0' into the last two ($F051-$F057), which
# is why they looked like constants: they are this path's values of two real
# fields.
OFF_CONT = 8      # $070C -- continuation code, '1'..'4'   ($EF6C)
OFF_SEQ = 9       # $070D -- block sequence digit          ($EE8B, vs $6E48)


def build_header(data_len: int, cont: bytes = b"4", seq: bytes = b"0") -> bytes:
    """The 10-byte header $F00F writes for a payload carrying data_len bytes.

    cont/seq default to the values the card itself emits, so the one-argument
    call is unchanged.  A reply uses the same layout with cont/seq meaning
    something -- see build_reply().
    """
    if not 0 <= data_len <= 999:
        raise ValueError("data length must fit three decimal digits")
    if len(cont) != 1 or len(seq) != 1:
        raise ValueError("cont and seq are single bytes")
    return b"10" + f"{data_len:03d}".encode() + b"000" + cont + seq


def split_payload(payload: bytes):
    """(header, data, declared_len, consistent) for a received payload."""
    if len(payload) < HDR_LEN:
        return b"", b"", None, False
    hdr, data = payload[:HDR_LEN], payload[HDR_LEN:]
    try:
        declared = int(hdr[2:5])
    except ValueError:
        return hdr, data, None, False
    return hdr, data, declared, declared == len(data)


def encode(payload: bytes, terminator: int = 0x0D) -> bytes:
    """Wrap an already-built payload the way the card does: checksum, ETX, CR."""
    return payload + checksum(payload) + bytes([0x03, terminator])


def encode_data(data: bytes, terminator: int = 0x0D) -> bytes:
    """Build a complete frame around a data field: header, checksum, ETX, CR."""
    return encode(build_header(len(data)) + data, terminator)


def decode(frame: bytes):
    """Split a received frame and check it.

    Returns (payload, ok).  Trailing $03/$0D are optional because the card does
    not always emit the ETX -- the 2026-08-08 capture ended ck1 ck2 $0D with no
    $03, so do not require it.
    """
    f = frame
    while f and f[-1] in (0x0D, 0x0A, 0x03):
        f = f[:-1]
    if len(f) < 3:
        return b"", False
    payload, ck = f[:-2], f[-2:]
    return payload, checksum(payload) == ck


# --- the server -> card direction -------------------------------------------
#
# HOW CPU2 DECIDES A BLOCK IS OVER -- and the trap that cost a bench run.
#
# $E6AF: LDX $8A / BEQ (length path) / CMP $8A / BEQ (emit)
#
# **SMC never issues a $69 command**, so CPU2 keeps its built-in default block
# from $FDCF: $8A = $03, $8F = $FC, $8E = $00.  Which means, for SMC:
#
#   * a block ends at the FIRST $03 -- ETX-terminated, variable length;
#   * $8F = 252 is only a fallback cap, not the size;
#   * $8E = 0, so there is NO inter-character flush to rescue a block that
#     never contains an ETX.  It would simply never be delivered.
#
# $8A = $00 / $8F = $30 (fixed 48-byte packets) is a different card's override,
# not this one's.  It matters for the "0005" reply, whose record can carry an
# $03 in the middle: CPU2 cuts the block at that $03, the card finds no
# checksum, NAKs with "0101" ($ED57 copies it from $F41D), and the leftover
# tail arrives as a second bad block -- two hits
# on the $F305 retry counter, i.e. error 4701, in 2.4 seconds.
#
# So: **a reply may be any length, and must contain no $03 except the last
# byte.** That is why $ACDD takes $04 as well as $03 as a record terminator --
# $04 is the one that can appear INSIDE a block.
#
# $EF32 then copies ($0702 - $0D) bytes -- the delivered count minus 13 -- from
# $070E into card WRAM at $6100, growing until $69xx (error 4703).

REPLY_LEN = 48          # a convenient default, NOT a constraint (see above)
REPLY_DATA_LEN = REPLY_LEN - HDR_LEN - 3    # 35
ETX = 0x03

# One block, and the W-RAM the blocks of one message are assembled in.
BLOCK_MAX = 252                             # CPU2's $8F fallback cap
BLOCK_DATA_MAX = BLOCK_MAX - HDR_LEN - 3    # 239 -- header, ck1 ck2 $03
WRAM_IN = 0x6100        # $EFEA seeds the write pointer $6E29/$6E2A here
WRAM_IN_TOP = 0x6900    # $EF53: once its high byte reaches $69 -> 4703
WRAM_IN_MAX = WRAM_IN_TOP - WRAM_IN         # 2048 bytes for a whole message

# Request codes: the first four data bytes.  The card's own requests are built
# from ROM constants (bank 6 $8560 for the login, $8738 for the next one).
REQ_LOGIN = b"0001"           # bank 6 $85C7, sent by $85D1
REQ_0004 = b"0004"            # bank 6 $8779, sent by $87A0's sequencer
# Replies, as tested by bank 6 $8658 / $867A against WRAM $6100..$6103.
RESP_LOGIN_OK = b"0002"       # $8676 -- accepted, the session proceeds
RESP_LOGIN_NOTICE = b"0003"   # $8698 -- routes to $E530, the notice screen
# Replies to "0004", tested by bank 6 $8852 / $8874 and bank 7 $F427 / $F448.
RESP_0004_OK = b"0005"        # $8870 -> $884F returns 0 -> $FE69, on into $A800
RESP_0004_RETRY = b"0006"     # $8892 -> $884C returns 1 -> $FE5D, PIN re-entry
RESP_0004_AGAIN = b"0102"     # $F444 -> $8841, card re-sends the same request
RESP_0004_NOTICE = b"0201"    # $F465 -> $E530, the notice screen

# --- the '1' request family --------------------------------------------------
#
# The login and "0004" requests carry a literal 10-byte code copied out of ROM
# ($85C7, $8779).  Everything the card sends AFTER the menu is drawn is
# assembled instead by bank 7 $F374, and its prefix is FIELDS, not a code:
#
#   $6000    '1'                      constant ($F374)
#   $6001-3  "000" while $6E80 == 1   the page/section digits.  $6E80 is 1 on
#            else $0501-$0503         the bank-5 content path ($FE83) and 0 on
#                                     the $03-terminator path ($FE8B), where
#                                     $F3C6 fills them from $0501 instead
#   $6004-5  $60 / $61                the caller's two-character command
#   $6006-9  "0000"                   constant
#   $600A+   $6E49 payload bytes;     $F3BC then adds 10 for the prefix itself
#
# So split_payload()'s "code" -- data[0:4] -- is '1' plus the section, and the
# command lives at data[4:6].  Keying rules on data[0:4] would key them on the
# page number, which is why request_key() exists.
#
# Observed on the menu page:
#
#   1001100040  1000130000M  88 99 03
#   header      '1' "000" "13" "0000" 'M'
#
# bank 2 $B326 is the builder: $60/$61 = '1','3', and one payload byte at
# $600A -- 'M' ($B359), or the current selection ($72CB, $71A3 bytes, led by
# $72C9 | $30) when the key in $82 was $42.
REQ_PAGE = b"1*13"            # bank 2 $B326 -> $F374, command "13"

# A second builder, bank 7 $EE9C, lays the same ten bytes out differently:
# '1', then $60/$61/$62, then the literal "132000" from $EEC1.  It belongs to
# the $EE07 sequencer, not to $F374's, and request_key() keeps them apart by
# data[6:10] -- "0000" for $F374, "2000" for $EE9C.
_PAGE_SPARE = b"0000"


def request_key(data: bytes) -> bytes:
    """What identifies a request: a code for some, a command field for others.

    The card has two request shapes and only the '0' family is identified by
    its first four bytes.  For the '1' family that field is the page number,
    so the key is ``b"1*"`` plus the two-byte command at data[4:6].
    """
    if data[:1] == b"1" and data[6:10] == _PAGE_SPARE:
        return b"1*" + bytes(data[4:6])
    return bytes(data[:4])


def split_request(data: bytes):
    """Decompose a '1'-family request, or return None if it is not one.

    -> {"section", "command", "spare", "payload"} as bytes.
    """
    if request_key(data)[:2] != b"1*":
        return None
    return {"section": bytes(data[1:4]), "command": bytes(data[4:6]),
            "spare": bytes(data[6:10]), "payload": bytes(data[10:])}

# $EF6C's continuation table, indexed [is_first_block][cont] -> $6E25.  "First"
# is decided by the POINTER ($6E29/$6E2A still $6100), not by a block count, so
# a discarded block leaves the next one still first.  $6E25 then indexes the
# jump table at $EDD7:
#
#   0  $EDE2  $EF32 copy, $EE8B seq, $EFBF, $F3F8 -> RTS      copy and finish
#   1  $EDEF  $EF32 copy, $EE8B seq, $EFBF, $EF1F -> $ED9D    copy, expect more
#   2  $EDFE  $EFBF -> $ED9D                                  discard, expect more
#   3  $EE04  JMP $E5BC                                       4702
#
# So the sequence check runs on BOTH copy arms -- it is not a multi-block
# speciality -- and the discard arm skips it.  $EF1F steps $6E48 '0'..'9' and
# wraps, and only arm 1 does that, so the digit counts COPIED blocks.
_CONT = {
    True: {ord("1"): 1, ord("2"): 2, ord("3"): 2, ord("4"): 0},
    False: {ord("1"): 3, ord("2"): 1, ord("3"): 0, ord("4"): 3},
}
_CONT_COPIES = (0, 1)           # the arms that run $EF32 and $EE8B
_CONT_EXPECTS_MORE = (1, 2)     # the arms that go back to $ED9D


def next_seq(seq: bytes) -> bytes:
    """`$EF1F`: '0'..'9' and wrap.  Only arm 1 calls it."""
    return b"0" if seq == b"9" else bytes([seq[0] + 1])


def build_reply(data: bytes, cont: bytes = b"4", seq: bytes = b"0",
                pad: bytes = b"0") -> bytes:
    """One inbound block: header + data + ck1 + ck2 + $03.

    data is padded to REPLY_DATA_LEN with `pad` ('0', matching the card's own
    $EFC5 buffer prefill, so padding is indistinguishable from untouched
    buffer at the far end too), giving the 48-byte block both hardware-proven
    sessions used.  cont defaults to '4' = a single complete message, the only
    code bank 6 $85D1 accepts for the login reply.

    **pad=None sends the data unpadded**, and for the "0005" content reply that
    is mandatory, not cosmetic.  $EF32 appends each block's data at the running
    pointer $6E29/$6E2A and bank 6 $8812 then calls $F3F8, which writes $03 at
    exactly that pointer -- so the card's own ETX lands one byte past whatever
    we send.  Bank 5's $BCE4 walks the content stream until it reads that $03,
    and padding puts '0' bytes in front of it, which $881D rejects as 4980.
    Measured on hardware, serve6, 2026-08-08.
    """
    if len(data) > REPLY_DATA_LEN and pad is not None:
        raise ValueError(f"data is {len(data)}B, max {REPLY_DATA_LEN} per block")
    if len(data) > BLOCK_DATA_MAX:
        raise ValueError(f"data is {len(data)}B; CPU2's $8F caps a block at 252")
    if pad is not None and len(pad) != 1:
        raise ValueError("pad is a single byte, or None for no padding")
    if ETX in data:
        # CPU2 would cut the block here and the card would never find the
        # checksum.  This is error 4701 in the making -- refuse to build it.
        raise ValueError(
            f"data contains $03 at offset {data.index(ETX)}: CPU2 ends the "
            "block at the first ETX ($8A = $03), so the card would see a "
            "truncated block. Use $04 where a record needs a terminator.")
    if pad == bytes([ETX]):
        raise ValueError("padding with $03 would truncate the block")
    if pad is not None:
        data = data + pad * (REPLY_DATA_LEN - len(data))
    payload = build_header(len(data), cont, seq) + data
    return payload + checksum(payload) + bytes([ETX])


# The login reply's 35 data bytes, as consumed by bank 6 $8658 and $86AC:
#
#   [0:4]   "0002"    the accept code           -- $8658 vs $8676
#   [4:10]  6 bytes   not read on the login path
#   [10]    key       -> zero page $8C          -- $86B5
#   [11:35] 24 bytes  Shift-JIS message text    -> $B60D -> $7600
#
# $8C is a challenge: $FC7E masks it to $0F and uses it to rotate which member
# number digits are summed into the four authenticator digits of the NEXT
# request ("0004").  Any value is legal -- the card just computes a different
# answer -- so '0' is a safe no-op default.
LOGIN_SPARE_LEN = 6
LOGIN_MSG_OFF = 11


def build_login_reply(message: bytes = b"", key: bytes = b"0",
                      spare: bytes = b"0" * LOGIN_SPARE_LEN, **kw) -> bytes:
    """Assemble the login reply from its fields.

    message is the Shift-JIS stream for the on-screen text; build it with
    message.py so it carries the `\\`+$FE end marker.  Anything
    shorter than 24 bytes is padded by build_reply().
    """
    if len(key) != 1:
        raise ValueError("key is a single byte")
    if len(spare) != LOGIN_SPARE_LEN:
        raise ValueError(f"spare must be {LOGIN_SPARE_LEN} bytes")
    room = REPLY_DATA_LEN - LOGIN_MSG_OFF
    if len(message) > room:
        raise ValueError(f"message is {len(message)}B, {room} fit in one block")
    return build_reply(RESP_LOGIN_OK + spare + key + message, **kw)


# --- replies to "0004" -------------------------------------------------------
#
# "0006" is fully understood: bank 6 $8896 runs data[10:] through the same
# $B60D layout engine the login reply used (destination $7680 this time), $88C0
# resets the four PIN tiles to the '?' placeholder and clears the cursor
# $70-$73, and $FE66 loops back to $FE52 -- the PIN entry screen.  So it means
# "wrong PIN, here is why, try again".
#
# "0005" is the accept path, and its payload is a RECORD, not a message.  $A800
# points $78/$79 at $610A and $AC67 parses from there:
#
#     <field1> '/' <field2> '/' <field3> '/' <field4> <$03 or $04>
#
# FOUR fields.  $ACD6 loops until $0520 reaches 6 in steps of 2, storing three
# pointers at $B2/$B4/$B6 -- and field 1 is the record start already in $B0.
# The terminator pointer lands in $B8/$B9, which $FE76 then dereferences: $04
# selects bank 5, $03 goes to $FE89.
#
# $AC67 does not stop there -- it falls through into a content parser that runs
# to about $AFC0, sets up two build buffers ($BA/$BB = $7920, $BC/$BD = $7AA0)
# and raises THIRTEEN distinct errors, 4940 through 494C, via $AFF0 -> $E5F8.
# All thirteen are decoded; the grammar, the name table and a builder live in
# content.py.  The shape is
#
#     <field1> '/' <field2> '/' <field3> '/' <field4> '/' <$03|$04>
#
# -- FOUR separators, not three: field 4 carries its own trailing '/' even when
# it is empty, and leaving it off is error 4948.  Field 1 is a list of menu
# entries; the first byte of each must be >= $80 ($AD37, error 4940, measured
# on hardware) because it is a name byte-code, not ASCII.
#
# This module stays ROM-free, so it validates only what can be checked without
# one.  Build records with content.build_record(), which runs them through
# the real parser and hands back the code the card would display.
MAX_ENTRIES_HINT = 16


def _0004_data(record: bytes, fields, term: int, spare: bytes,
               trailer: bytes) -> bytes:
    """The "0005" data field, validated; shared by both builders below."""
    if (record is None) == (fields is None):
        raise ValueError("pass exactly one of record= or fields=")
    if record is None:
        if len(fields) != 4:
            raise ValueError("$AC67 splits exactly four fields")
        if term != 0x04:
            raise ValueError("$03 terminates the CPU2 block; $AC67 records "
                             "must use $04 (see build_reply)")
        # Field 4 needs its own '/' before the terminator: $AEF6 checks
        # ($B6),0 == '/', and an empty field 4 sitting straight on the $04 is
        # error 4948.
        record = b"/".join(fields) + b"/" + bytes([term])
    terminated = bool(record) and record[-1] in (0x03, 0x04)
    if not record:
        raise ValueError("a record must have a body")
    if not terminated:
        # The unterminated form: the card's own $03 ($F3F8, one byte past the
        # block) terminates it, which is the $03 branch of $FE7A -- straight to
        # the record page, no trailer.  Nothing may follow it, or the $03 would
        # land after the trailer instead of after the record.
        if trailer:
            raise ValueError(
                "an unterminated record cannot carry a trailer: the card's "
                "$03 lands one byte past the LAST byte sent, so it would "
                "terminate the trailer rather than the record")
    if record[0] < 0x80:
        raise ValueError(
            f"the record starts with ${record[0]:02X}; $AD37 requires >= $80 "
            "and anything less is error 4940")
    body = record[:-1] if terminated else record
    for stray in (0x03, 0x04):
        i = body.find(stray)
        if i >= 0:
            raise ValueError(
                f"stray ${stray:02X} at record offset {i}: $ACDD takes the "
                "first $03/$04 in field 4 as the terminator, so the record "
                "would be cut short (it surfaces later as 4949)")
    # The trailer sits AFTER the terminator, and $ACDD's scan starts at field 4
    # and stops on the terminator, so it never reaches these bytes -- an $04
    # here is fine (a tile coordinate of 4, say).  $03 is not: CPU2 would cut
    # the block.  build_reply catches that too; this names the cause.
    j = trailer.find(0x03)
    if j >= 0:
        raise ValueError(
            f"$03 at trailer offset {j}: CPU2 ends the block at the first "
            "ETX, so the content stream would be truncated")
    return RESP_0004_OK + spare + record + trailer


def build_0004_reply(record: bytes = None, fields=None, term: int = 0x04,
                     spare: bytes = b"0" * 6, trailer: bytes = b"", **kw) -> bytes:
    """The "0005" accept: a content record for $AC67, then its trailer.

    Pass `record` -- a complete record ending in its terminator, as built by
    content.build_record().  `fields` is the low-level alternative: the
    four field bodies, joined here with the four separators $AC67 wants.

    `trailer` is what follows the terminator.  With an $04 the record is NOT
    the end of the reply: $FE76 hands that terminator to bank 5, which reads a
    header block starting at terminator+1 and validates it at $87AF.  Leaving
    the trailer empty puts the block's '0' padding there, which is error 4970.
    content.check_trailer() runs $87AF over a candidate.

    An UNTERMINATED record -- content.build_record(term=None) -- takes the
    other branch of $FE7A: the card's own $03 terminates it, $6E80 stays 0 and
    $A847 draws the record page immediately, with no content page in front of
    it.  Nothing may follow such a record, so `trailer` must be empty.

    term defaults to $04, not $03.  $ACDD accepts either, but an $03 inside the
    block is where CPU2 cuts it -- see the note above build_reply().
    """
    return build_reply(_0004_data(record, fields, term, spare, trailer), **kw)


def build_0004_blocks(record: bytes = None, fields=None, term: int = 0x04,
                      spare: bytes = b"0" * 6, trailer: bytes = b"",
                      limit: int = BLOCK_DATA_MAX, **kw):
    """The "0005" accept as however many blocks it takes.

    $EF32 reassembles the message at $6100 before $FE76/$AC67 ever look, so a
    record longer than one block splits like any other reply; the boundary may
    fall anywhere.  For the unterminated form the card's $03 lands one byte
    past the LAST block's data, exactly as in the single-block case.  Returns
    a list; a reply that fits is a list of one, byte-identical to
    build_0004_reply().
    """
    return build_blocks(_0004_data(record, fields, term, spare, trailer),
                        limit=limit, **kw)


def build_0004_retry(message: bytes = b"", spare: bytes = b"0" * 6,
                     **kw) -> bytes:
    """The "0006" reject: a message, then the card asks for the PIN again."""
    return build_reply(RESP_0004_RETRY + spare + message, **kw)


# --- replies to the '1' family ($F374 requests) ------------------------------
#
# bank 6 $A03C classifies the reply and hands an index 0-4 to $FEC8's jump
# table.  It looks at exactly two things:
#
#   1. data[0:4] == "0202"  ($F469)             -> index 0, immediately
#   2. otherwise data[4:6] against the six-pair table at bank 6 $A030,
#      "12" "14" "54" "56" "58" "50"; anything else also falls through to 0.
#
# Index 0 is bank 5 $8000, and that is the whole point: $8000 reads $610A --
# reply data[10] -- and unless its high nibble is $A0 (hang up, $805F ->
# $FEA0) it sets $BE = 5 and dispatches to $80B7, which is the SAME header +
# token stream the "0005" record's trailer uses:
#
#   $80BB  JSR $87AF                   validate the header at $610A/$610B
#   $80BE  $B0 = $610A
#   $80C6  count = (($B0),1 & $0F) + 2 ; $8B92 steps $B0 past the header
#   $80D2  $B2/$B3 = $71D7             the build buffer (vs $7AA0 there)
#   $80F3  until ($B0),0 == $03: $81E0 then $88D0    -- identical to $BCE4
#
# So a reply to a '1' request is a content page and nothing else; there is no
# $AC67 record in front of it.  $80B7 then sets $BE = 6 -> $813B -> $BE = 7 ->
# $8170, the page's interactive loop.
#
# The header's two bytes are that loop's button bindings, not filler:
#   b0 & $03  bank 5 $9EC8, on 目次 ($82 == $45): 0 nothing, 1 hang up, 2 or 3
#             re-request "13" (3 skips the 通信中 animation via $6E47).
#   b1        bank 5 $9EDF, on 実行 ($82 == $42): inert while b1 & $0F == 0 or
#             b1 & $F0 == $80.  The live form is not decoded.
RESP_PAGE_OK = b"0202"        # $F469 -> index 0 regardless of data[4:6]
RESP_PAGE_SUB = b"12"         # $A030 -> index 0, the content-page path
# data[4:6] -> $FEC8's index, from the table at bank 6 $A030.
PAGE_SUBCODES = {b"12": 0, b"14": 0, b"54": 1, b"56": 2, b"58": 3, b"50": 4}
PAGE_HANDLERS = {
    0: "bank 5 $8000 -> $80B7, a content page at data[10]",
    1: "$FEDE -> bank 2 $906B",
    2: "$FEE6 -> bank 2 $8030",
    3: "$FEEE -> bank 2 $803E",
    4: "$FEB0 -> bank 2 $A700",
}
PAGE_BODY_OFF = 10


def page_action(data: bytes) -> int:
    """$A03C's verdict on a reply to a '1' request: the $FEC8 jump index."""
    if data[:4] == RESP_PAGE_OK:
        return 0
    return PAGE_SUBCODES.get(bytes(data[4:6]), 0)


def build_page_reply(content: bytes, code: bytes = RESP_PAGE_OK,
                     sub: bytes = RESP_PAGE_SUB, spare: bytes = b"0" * 4,
                     pad=None, **kw) -> bytes:
    """A content page in answer to a '1' request.

    `content` is the `$87AF` header and the token stream behind it, exactly as
    for the "0005" trailer -- build it with content.build_content() and
    check it with content.check_content(), which models $87AF, $881D and
    $88D0 on the same code bank 5 runs here.

    **pad defaults to None and must stay there.**  $F3F8 writes the stream's
    $03 one byte past our last, so padding would sit between the tokens and
    their terminator; that is 4980, measured on the "0005" path (serve6).
    """
    for name, want, got in (("code", 4, code), ("sub", 2, sub),
                            ("spare", 4, spare)):
        if len(got) != want:
            raise ValueError(f"{name} is {len(got)}B, must be {want}")
    if len(content) < 2:
        raise ValueError("$87AF reads $610A and $610B, so the content needs "
                         "at least its two header bytes")
    if content[0] & 0xF0 == 0xA0:
        raise ValueError(
            f"header b0 = ${content[0]:02X}: bank 5 $8000 reads $610A first "
            "and an $Ax high nibble means hang up ($805F -> $FEA0)")
    return build_reply(code + sub + spare + content, pad=pad, **kw)


# --- the "0004" authenticator ------------------------------------------------
#
# $FC7E, driven from bank 6 $8751 while building the "0004" request.  $6F00 is
# ten ASCII digits -- "0", "0", then the eight-digit member number ($88FB copies
# it from $6A06, mapping the ' ' fill to '0') -- and $6F0A-$6F0D is the 4-digit
# PIN the operator types at the 暗証番号 prompt ($89EC stores each keypress
# there, indexed by the cursor $73).  The four digits are computed in place:
#
#     key = $8C & $0F                    ; the byte WE sent at reply data[10]
#     for i in 0..3:
#         y  = i + 5
#         y2 = y - key ; if y2 < 0: y2 += 10      ; single conditional add
#         out[i] = (buf[y] + buf[y2] + out[i]) mod 10
#
# $E659 does each addition: mask both operands with $0F, add, subtract 10 on
# overflow, ORA #$30.  Note key == 0 makes y2 == y, so the same digit is added
# twice -- with our default reply the four digits are (2*d + pin) mod 10.

def _add10(a: int, b: int) -> int:
    """$E659 -- ASCII digit addition mod 10."""
    t = (a & 0x0F) + (b & 0x0F)
    if t >= 10:
        t -= 10
    return t | 0x30


def auth_digits(buf10: bytes, pin: bytes, key: int) -> bytes:
    """$FC7E: the four digits the card puts at the end of the "0004" request."""
    if len(buf10) != 10 or len(pin) != 4:
        raise ValueError("buf10 is 10 digits ($6F00-$6F09), pin is 4")
    key &= 0x0F
    out = bytearray(pin)
    for i in range(4):
        y = i + 5
        y2 = y - key
        if y2 < 0:                      # $FC9B: BCS / CLC / ADC #$0A
            y2 += 10
        out[i] = _add10(_add10(buf10[y], buf10[y2]), out[i])
    return bytes(out)


def recover_pin(buf10: bytes, digits: bytes, key: int) -> bytes:
    """Invert auth_digits -- what PIN produces these four digits?

    Every step is addition mod 10, so this is exact, not a search.  It turns a
    captured "0004" request into a check on the whole model: the recovered PIN
    is either the one that was typed or the model is wrong.
    """
    key &= 0x0F
    out = bytearray(4)
    for i in range(4):
        y = i + 5
        y2 = y - key
        if y2 < 0:
            y2 += 10
        mix = _add10(buf10[y], buf10[y2]) & 0x0F
        out[i] = ((digits[i] & 0x0F) - mix) % 10 | 0x30
    return bytes(out)


def split_0004(data: bytes):
    """("0004000000", member[8], digits[4]) for a request built by $8738."""
    if len(data) != 22:
        return None
    return data[:10], data[10:18], data[18:22]


def card_verify(block: bytes, first_block: bool = True,
                mailbox_type: int = 0xC0, expect_type: int = 0xC0,
                expect_seq: bytes = b"0", check_seq=None) -> dict:
    """Run the card's own acceptance checks over one inbound block.

    `block` is what lands at $0704 -- the mailbox payload, without CPU2's
    three-byte [$C0][count][errors] preamble.  mailbox_type is the $0701 byte
    CPU2 supplies ($C0 for received data).

    Returns a dict; ["error"] is the four-digit code the card would put on
    screen, or None if the block is accepted.  The checks are in the card's
    order, and each one names the routine it comes from.
    """
    r = {"error": None, "where": None, "declared": None, "cont": None,
         "action": None, "data": b""}

    def fail(code, where):
        r["error"], r["where"] = code, where
        return r

    # $F145 -- the caller's inline byte vs $0701.  Two known alternatives get
    # their own display code with the first payload byte as the low pair
    # ($E55C: $41 -> 44xx, $42 -> 45xx); anything else is 46 + $0701.
    if mailbox_type != expect_type:
        first = block[0] if block else 0
        if mailbox_type == 0xE0:
            return fail(f"44{first:02X}", "$F145 -> $E0")
        if mailbox_type == 0xE1:
            return fail(f"45{first:02X}", "$F145 -> $E1")
        return fail(f"46{mailbox_type:02X}", "$F145 wrong reply type")

    # $F185 -> $E6AC: three digits at offset 2, ASCII-masked (AND #$0F) and
    # accumulated x10, so a non-digit does not fault -- it just decodes wrong.
    if len(block) < HDR_LEN:
        return fail("46C0", "$F185 short block")
    declared = 0
    for c in block[2:5]:
        declared = declared * 10 + (c & 0x0F)
    r["declared"] = declared

    # $F18B: sum over declared+10 bytes, then ck1, ck2, $03.  Any mismatch
    # sets $6E21 = $21, which $E55C renders as 46 + $0701.
    end = declared + HDR_LEN
    if len(block) < end + 3:
        return fail("46C0", "$F18B checksum runs off the end")
    if bytes(block[end:end + 2]) != checksum(bytes(block[:end])):
        return fail("46C0", "$F18B checksum mismatch")
    if block[end + 2] != 0x03:
        return fail("46C0", "$F18B missing ETX")

    # $EF6C: continuation code.  Note the fall-through -- a byte outside
    # '1'..'4' lands on $EFA0 and reads as action 0, it is not an error.
    cont = block[OFF_CONT]
    r["cont"] = chr(cont)
    action = _CONT[first_block].get(cont, 0)
    r["action"] = action
    if action == 3:
        return fail("4702", f"$EF6C: cont {chr(cont)!r} invalid here")

    # $EE8B, which arms $EDE2 and $EDEF both call and $EDFE does not -- so it
    # follows the action unless the caller forces it.  card_receive() passes
    # False and runs it itself, because $EF32 copies BEFORE $EE8B rules and a
    # block can therefore be both written to W-RAM and rejected.
    if check_seq is None:
        check_seq = action in _CONT_COPIES
    if check_seq and bytes(block[OFF_SEQ:OFF_SEQ + 1]) != expect_seq:
        return fail("4705", "$EE8B sequence digit mismatch")

    # $EF32 takes its copy length from the MAILBOX count, not from the header,
    # so a block whose count disagrees with DDD passes every check above and
    # then copies the wrong number of bytes into WRAM.  Flag it.
    copy_len = len(block) - 13
    r["data"] = bytes(block[HDR_LEN:HDR_LEN + copy_len]) if copy_len > 0 else b""
    if copy_len != declared:
        r["warning"] = (f"$EF32 copies {copy_len}B (count-13) but the header "
                        f"declares {declared}B")
    return r


def card_receive(blocks, base: int = WRAM_IN) -> dict:
    """Feed a whole message to the card's receive path, block by block.

    This is `$EF6C` -> `$EDD7` -> `$EF32`/`$EE8B`/`$EF1F` as a state machine:
    a message is assembled from as many blocks as it takes, appended at
    `$6E29`/`$6E2A`, and the card writes the stream's `$03` after the last one
    (`$F3F8`).  So `["data"]` is exactly what `$6100` holds when bank 5 starts
    walking it, and a split is invisible to `$AC67` and `$BCE4`.

    `["complete"]` is False when the blocks run out while an arm was still
    expecting another -- the card does not fault, it simply keeps waiting at
    `$ED9D`, which on the bench looks like a hang rather than an error code.
    """
    r = {"error": None, "where": None, "data": b"", "complete": False,
         "blocks": [], "ptr": base}
    ptr, seq, out = base, b"0", bytearray()
    for i, block in enumerate(blocks):
        # $EF6C reads the POINTER, not a counter.
        v = card_verify(block, first_block=(ptr == base), check_seq=False)
        step = {"n": i, "cont": v["cont"], "action": v["action"],
                "seq": chr(block[OFF_SEQ]) if len(block) > OFF_SEQ else None,
                "expect_seq": seq.decode(), "error": v["error"]}
        r["blocks"].append(step)
        if v["error"]:
            r["error"], r["where"] = v["error"], v["where"]
            return r
        action = v["action"]
        if action in _CONT_COPIES:
            # $EF32: length is the mailbox count minus 13, the pointer moves
            # FIRST, and $EF53 faults once its high byte reaches $69.
            n = len(block) - 13
            if n > 0:
                if ptr + n >= WRAM_IN_TOP:
                    r["error"] = "4703"
                    r["where"] = f"$EF53: {ptr + n:#06x} is past ${WRAM_IN_TOP:04X}"
                    return r
                out += v["data"]
                ptr += n
            # ...and only then does $EE8B rule on the digit.
            if bytes(block[OFF_SEQ:OFF_SEQ + 1]) != seq:
                r["error"] = "4705"
                r["where"] = (f"$EE8B: block {i} carries "
                              f"{chr(block[OFF_SEQ])!r}, $6E48 is {seq.decode()!r}")
                r["data"], r["ptr"] = bytes(out), ptr
                return r
        if action == 1:
            seq = next_seq(seq)         # $EF1F, arm 1 only
        r["data"], r["ptr"] = bytes(out), ptr
        if action not in _CONT_EXPECTS_MORE:
            r["complete"] = True
            return r
    return r


def split_reply(data: bytes, limit: int = BLOCK_DATA_MAX):
    """`data` cut into (chunk, cont, seq) triples the card will reassemble.

    The continuation codes come straight out of `_CONT`: the first block says
    `'1'` when more follow and `'4'` when it is the whole message, and a later
    one says `'2'` or `'3'`.  The digit counts copied blocks, so it advances on
    every chunk here -- none of these are the discard arm.

    A chunk boundary may fall anywhere: `$EF32` appends bytes and nothing looks
    at them until `$F3F8` has written the terminator after the last block.
    """
    if limit < 1 or limit > BLOCK_DATA_MAX:
        raise ValueError(f"limit is 1..{BLOCK_DATA_MAX}")
    if len(data) > WRAM_IN_MAX:
        raise ValueError(
            f"{len(data)}B of data: $EF32 appends from ${WRAM_IN:04X} and "
            f"$EF53 faults at ${WRAM_IN_TOP:04X}, so a message is "
            f"{WRAM_IN_MAX}B at most (4703)")
    chunks = [data[i:i + limit] for i in range(0, len(data), limit)] or [b""]
    out, seq = [], b"0"
    for i, chunk in enumerate(chunks):
        last = i == len(chunks) - 1
        if i == 0:
            cont = b"4" if last else b"1"
        else:
            cont = b"3" if last else b"2"
        out.append((chunk, cont, seq))
        seq = next_seq(seq)
    return out


def build_blocks(data: bytes, limit: int = BLOCK_DATA_MAX, **kw):
    """`split_reply()`, then one `build_reply()` per chunk.  pad stays None:
    padding is only ever right for the fixed-size login block."""
    return [build_reply(chunk, cont=cont, seq=seq, pad=None, **kw)
            for chunk, cont, seq in split_reply(data, limit)]


def build_page_blocks(content: bytes, code: bytes = RESP_PAGE_OK,
                      sub: bytes = RESP_PAGE_SUB, spare: bytes = b"0" * 4,
                      limit: int = BLOCK_DATA_MAX, **kw):
    """A content page as however many blocks it takes.

    The 10-byte code+sub+spare prefix belongs to the MESSAGE, not to each
    block, so it is spent once and every further block is `limit` bytes of
    pure content.  Returns a list; a page that fits is a list of one and is
    byte-identical to build_page_reply().
    """
    return build_blocks(code + sub + spare + content, limit=limit, **kw)


def _selftest() -> int:
    # The exact bytes the card sent on 2026-08-08 after CONNECT + "COM".
    body = b"10027000400001000000F3437974000100200"
    want = bytes([0x8E, 0xBD])
    got = checksum(body)
    ok = got == want
    print(f"payload  : {body.decode()}")
    print(f"expected : {want.hex(' ')}")
    print(f"computed : {got.hex(' ')}")
    print("self-test:", "PASS" if ok else "FAIL")

    payload, valid = decode(encode(body))
    print("roundtrip:", "PASS" if (payload == body and valid) else "FAIL")

    hdr, data, declared, consistent = split_payload(body)
    print(f"header   : {hdr.decode()}  (declares {declared} data bytes)")
    print(f"data     : {data.decode()}")
    hdr_ok = consistent and build_header(len(data)) == hdr
    print("header   :", "PASS" if hdr_ok else "FAIL")

    rebuilt = encode_data(data)
    full = body + want + b"\x0d"          # the capture had no $03
    rb_ok = rebuilt[:-2] == body + want
    print("rebuild  :", "PASS" if rb_ok else "FAIL")

    # --- server -> card ------------------------------------------------------
    print()
    reply = build_login_reply()
    v = card_verify(reply)
    size_ok = len(reply) == REPLY_LEN and reply[-1] == 0x03
    print(f"reply    : {reply.decode('ascii', 'replace')}")
    print(f"           {len(reply)}B, ends ${reply[-1]:02X}, ck {reply[45:47].hex(' ')}")
    print("size     :", "PASS" if size_ok else "FAIL",
          f"(must be {REPLY_LEN} = CPU2 $8F, ETX inside, no CR)")
    accept_ok = (v["error"] is None and v["action"] == 0
                 and v["data"][:4] == RESP_LOGIN_OK and "warning" not in v)
    print(f"verify   : error={v['error']} declared={v['declared']} "
          f"cont={v['cont']!r} action={v['action']}")
    print("accept   :", "PASS" if accept_ok else "FAIL",
          "(bank 6 $8658 wants data[0:4] == \"0002\")")

    # Every rejection path, exercised rather than asserted.  Each entry:
    # (mutation, expected on-screen code).
    def bad_checksum():
        b = bytearray(reply); b[45] ^= 0x01; return bytes(b), {}

    def bad_etx():
        b = bytearray(reply); b[47] = 0x0D; return bytes(b), {}

    def bad_cont_first():
        return build_login_reply(cont=b"1"), {"first_block": False}

    def bad_seq():
        return build_login_reply(seq=b"7"), {"check_seq": True}

    cases = [
        ("checksum -> 46C0", bad_checksum, "46C0"),
        ("no ETX   -> 46C0", bad_etx, "46C0"),
        ("cont '1' late -> 4702", bad_cont_first, "4702"),
        ("seq '7'  -> 4705", bad_seq, "4705"),
        ("type $E1 -> 45xx", lambda: (reply, {"mailbox_type": 0xE1}),
         f"45{reply[0]:02X}"),
        ("type $12 -> 4612", lambda: (reply, {"mailbox_type": 0x12}), "4612"),
    ]
    errs_ok = True
    for name, make, want_code in cases:
        blk, kw = make()
        got = card_verify(blk, **kw)["error"]
        good = got == want_code
        errs_ok &= good
        print(f"  {name:24} got {got}  {'PASS' if good else 'FAIL'}")
    print("errors   :", "PASS" if errs_ok else "FAIL")

    # --- multi-block replies ------------------------------------------------
    #
    # A message longer than one block is assembled at $6100 by $EF32, and the
    # card's own $03 lands after the LAST block ($F3F8) -- so the split has to
    # be invisible to whatever walks the buffer afterwards.  That is the claim
    # these check: reassembled bytes identical, and every failure mode reached.
    print()
    print("multi-block ($EF6C -> $EDD7 -> $EF32/$EE8B/$EF1F):")
    mb_ok = True

    def mb(what, good):
        nonlocal mb_ok
        mb_ok &= good
        print(f"  {'ok  ' if good else 'FAIL'} {what}")

    page = bytes([0x82, 0x80]) + bytes(range(0x80, 0xC0)) * 8   # 514B, no $03
    whole = RESP_PAGE_OK + RESP_PAGE_SUB + b"0000" + page
    blocks = build_page_blocks(page)
    got = card_receive(blocks)
    mb(f"{len(page)}B page -> {len(blocks)} blocks "
       f"{[(chr(b[OFF_CONT]), chr(b[OFF_SEQ])) for b in blocks]}",
       len(blocks) == 3)
    mb("reassembles byte-identical at $6100",
       got["error"] is None and got["complete"] and got["data"] == whole)
    mb(f"write pointer ends at ${got['ptr']:04X}",
       got["ptr"] == WRAM_IN + len(whole))
    # One block must stay exactly what it always was.
    small = bytes([0x82, 0x80, 0x80, 0x81, 0x85, 0x8C, 0x97, 0x84, 0x80, 0x80,
                   0x41, 0x5C, 0xFE])
    mb("a page that fits is still one build_page_reply() block",
       build_page_blocks(small) == [build_page_reply(small)])

    # $EF32 copies BEFORE $EE8B rules, so a bad digit still moves the pointer.
    bad = list(blocks)
    b1 = bytearray(bad[1]); b1[OFF_SEQ] = ord("7")
    bad[1] = bytes(b1[:HDR_LEN]) + bytes(b1[HDR_LEN:-3]) + \
        checksum(bytes(b1[:len(b1) - 3])) + bytes([ETX])
    v = card_receive(bad)
    mb("a wrong sequence digit is 4705", v["error"] == "4705")
    mb("...and $EF32 had already copied that block",
       len(v["data"]) == len(blocks[0]) - 13 + len(blocks[1]) - 13)

    # The discard arm never runs $EE8B and never moves the pointer, so the
    # block after it is still "first" as far as $EF6C is concerned.
    dis = [build_reply(b"ignored", cont=b"2", seq=b"9", pad=None)] + blocks
    v = card_receive(dis)
    mb("cont '2' first: discarded, and the next block is still first",
       v["error"] is None and v["data"] == whole and v["blocks"][0]["action"] == 2)

    # Running out of blocks is not an error -- the card waits at $ED9D.
    v = card_receive(blocks[:1])
    mb("a truncated message hangs rather than faults",
       v["error"] is None and not v["complete"])

    # $EF53's ceiling, and the builder's refusal to walk into it.
    over = False
    try:
        split_reply(bytes(WRAM_IN_MAX + 1))
    except ValueError:
        over = True
    mb(f"split_reply refuses more than {WRAM_IN_MAX}B (4703)", over)
    v = card_receive(build_blocks(bytes(WRAM_IN_MAX), limit=BLOCK_DATA_MAX)
                     + [build_reply(b"x" * 40, cont=b"3", seq=b"0", pad=None)])
    mb("...and the model reaches 4703 when a block is forced past it",
       v["error"] == "4703")
    print("multiblk :", "PASS" if mb_ok else "FAIL")

    # --- the "0004" authenticator -------------------------------------------
    print()
    member = b"12345678"
    buf10 = b"00" + member
    pin = b"9876"
    # Round-trip every key: recover_pin must invert auth_digits exactly.
    inv_ok = all(recover_pin(buf10, auth_digits(buf10, pin, k), k) == pin
                 for k in range(16))
    print("auth inv :", "PASS" if inv_ok else "FAIL", "(all 16 keys)")
    # Key 0 is the degenerate case our default reply produces: y2 == y, so the
    # same digit is added twice.
    d0 = auth_digits(buf10, pin, 0)
    want0 = bytes(((2 * (buf10[i + 5] & 0xF) + (pin[i] & 0xF)) % 10) | 0x30
                  for i in range(4))
    key0_ok = d0 == want0
    print(f"auth key0: {d0.decode()} (2*d+pin mod 10 = {want0.decode()})",
          "PASS" if key0_ok else "FAIL")
    # The $03 guard.  This is the 4701 trap: an ETX anywhere but the last byte
    # makes CPU2 hand the card a truncated block.
    print()
    etx_ok = False
    try:
        build_reply(b"0005" + b"0" * 6 + b"0/0/0\x03")
        print("etx guard: FAIL (built a reply with an embedded $03)")
    except ValueError as exc:
        etx_ok = "offset" in str(exc)
        print("etx guard: PASS —", str(exc).split(":")[0])
    # The smallest record $AC67 accepts: one entry, ROM name $81, one item.
    # content.py proves that by running the parser; here we only check the
    # framing around it.
    rec = build_0004_reply(record=b"\x81\x7f\x81\x7f////\x04")
    rec_ok = rec.count(bytes([ETX])) == 1 and rec[-1] == ETX and 0x04 in rec
    print(f"0005 rec : {rec.count(bytes([ETX]))} ETX (must be 1, the last), "
          f"$04 terminator present: {0x04 in rec}",
          "PASS" if rec_ok else "FAIL")

    sep_ok = False
    try:
        build_0004_reply(fields=(b"\x81\x7f\x81\x7f", b"", b"", b""))
        sep_ok = True
    except ValueError as exc:
        print("0005 sep : FAIL —", exc)
    stray_ok = False
    try:
        build_0004_reply(record=b"\x81\x7f\x81\x04////\x04")
        print("0005 stray: FAIL (built a record with an embedded $04)")
    except ValueError as exc:
        stray_ok = "4949" in str(exc)
        print("0005 stray: PASS —", str(exc).split(":")[0])

    # --- multi-block "0005" --------------------------------------------------
    #
    # The menu record grown past one block: reassembly precedes $FE76/$AC67, so
    # the split must be invisible.  Grammar validity is content.py's business;
    # this checks the framing only.
    print()
    mb5_ok = True

    def mb5(what, good):
        nonlocal mb5_ok
        mb5_ok &= good
        print(f"  {'ok  ' if good else 'FAIL'} {what}")

    print('multi-block "0005" (build_0004_blocks):')
    lines = b"".join(b"%03d" % (101 + i) + b"T" * 22 for i in range(20))
    big = b"\x81\x7f" * 10 + b"/" + b"N" * 16 + b"/" + lines + b"//"
    blocks5 = build_0004_blocks(record=big)
    whole5 = RESP_0004_OK + b"0" * 6 + big
    got5 = card_receive(blocks5)
    mb5(f"{len(big)}B unterminated record -> {len(blocks5)} blocks",
        len(blocks5) == 3)
    mb5("reassembles byte-identical at $6100",
        got5["error"] is None and got5["complete"] and got5["data"] == whole5)
    small_rec = b"\x81\x7f\x81\x7f////\x04"
    mb5("a record that fits is still one build_0004_reply() block",
        build_0004_blocks(record=small_rec)
        == [build_0004_reply(record=small_rec, pad=None)])
    trl_ok = False
    try:
        build_0004_blocks(record=big, trailer=b"\x82\x80")
    except ValueError:
        trl_ok = True
    mb5("unterminated + trailer still refused", trl_ok)
    print("multiblk5:", "PASS" if mb5_ok else "FAIL")

    return 0 if all([ok, valid, hdr_ok, rb_ok, size_ok, accept_ok, errs_ok,
                     inv_ok, key0_ok, etx_ok, rec_ok, sep_ok, stray_ok,
                     mb5_ok]) else 1


if __name__ == "__main__":
    if len(sys.argv) > 1:
        data = sys.argv[1].encode()
        print(encode(data).hex(' '))
        sys.exit(0)
    sys.exit(_selftest())
