#!/usr/bin/env python3
"""WHAT THE SERVER SERVES.  Edit this file while a call is live.

server.py re-reads this file before every reply -- a stat() decides whether it
changed -- re-runs every offline check the card would run, and only then adopts
it.  A page the card would reject never reaches the wire: the previous good
version keeps serving and the error is logged at the terminal.

So the bench loop is no longer "edit, restart, re-dial":

    edit this file  ->  save  ->  the server logs `page reloaded`  ->
    press B (目次) on the Famicom  ->  the new page draws

B works as a reload button because PAGE13_B0's low two bits are 2: bank 5
`$9EC8` re-requests the same "13" page, and the next answer is whatever this
file says by then.  See server.py's PageSource.

**Change `EXPERIMENT` below and press B.**  One bench call runs the whole list.

WHAT THE SERVER LOOKS FOR HERE
------------------------------
    LOGIN_MESSAGE   str   Shift-JIS text for the login reply ($B60D)
    LOGIN_KEY       bytes reply data[10], the "0004" authenticator key
    REJECT_MESSAGE  str   text for the "0006" wrong-PIN reply (--reject)
    MENU_ENTRIES    list  the $AC67 record the "0005" accept carries
    MENU_CONTENT    bytes the content block behind that record
    page(req)       ->    the content block for a "13" page request
    INTERACTIVE     bool  what page(None) is EXPECTED to measure as, or None
                          to skip that guard

Everything else in here is this file's own business.

Keep side effects out of `page()`: it is called once per save (with
`req = None`, the loader's preview) and once per request (with the parsed
request dict).  It must return a page for `req = None`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import content  # noqa: E402


# ======================================================================
# THE DIAL.  Edit this, save, press B (目次).  Names are listed at the
# bottom in EXPERIMENTS; "form" is the known-good page from 2026-08-09.
# ======================================================================
EXPERIMENT = "probe"


# ---------------------------------------------------------------- login reply
#
# The on-screen text the login reply carries.  24 bytes fit in one block, and
# the engine draws them at column 4, row 12 (message.py).  Kept short and
# neutral -- it is our text, not a reconstruction of NTT's.
LOGIN_MESSAGE = "WELCOME"

# The key we put at reply data[10].  '0' -> $8C = 0, which makes $FC7E's two
# digit indices collide, so the four authenticator digits come out as
# (2*d + pin) mod 10.  Any value 0-15 is legal; this one is easy to check.
LOGIN_KEY = b"0"

# One block carries 25 bytes here (35 data - 10 before the message).  ASCII is
# one byte a character and Shift-JIS kana are two, so this is 23 characters of
# Latin or 11 of kana, plus the two-byte end marker.  A longer string is
# rejected rather than truncated.
REJECT_MESSAGE = "WRONG PIN NUMBER"


# ----------------------------------------------------------------- the "0005"
#
# The menu the "0005" accept carries.  $A800 hands the record to $AC67, whose
# grammar is in content.py; every entry here is a name byte-code resolved from
# the card's OWN 16-byte name table (bank 1 $8000), so the lines that appear
# are the card's own strings and not something we invented.
#
# $AC67 requires each entry to carry 1..8 (selector, parameter) pairs, >= $80
# and >= $7F.  The record page (the manual p.14 step 9) draws an entry
# as a MAIN MENU box picked with Left/Right, and its items as the SUB-MENU list
# above it, picked with Up/Down.
#
# A sub-menu line is 25 bytes and comes from ONE of two places, decided by the
# item selector.  Bank 7 $F507 reads the item byte and branches on $80:
#
#     >= $81   $87F0 + 25*(code - $81)   the card's 34-entry ROM directory
#      < $80   $7AA0 + 25*ordinal        an INLINE record, ours, out of field 3
#
# Either way $F4DA copies the 25 bytes to $0501, $F5A5 draws 22 of them from
# $0504 (LDX #$16), and $F3C6 sends $0501-$0503 -- the three it did NOT draw --
# as the next request's SECTION.  So an inline line says what we want and asks
# for a page we named, and the ROM directory stops being the vocabulary.
#
# That matters because the directory is mostly not this service: 001-010 and
# most of 013-034 are securities pages, and the manual's own sub-menus
# (全発売カレンダ, ソフトデータベース, 本日の情報案内 ...) are not in it at all.
# The real service must have sent inline records; content.page_titles() lists
# what the card ships, and content.submenu_record() builds ours.
#
# One line of each kind, on one screen:
#
#     line 1   inline, section "013"   draws as `INLINE OK      5. 1`
#     line 2   $8B, the ROM's 011 推奨ソフト速報
#
# Both draw, the ASCII as cleanly as the card's own Shift-JIS, and the three
# code digits do not appear -- $F5A5 renders 22 bytes from $0504, so the code
# is invisible metadata and the date column is just the tail of the title.
#
# EXPERIMENT = "probe" reads the other half back: put the cursor on a line,
# press A (実行), and the probe page prints the SECTION the card sent.
#
# MIND $6E80.  $F383 substitutes "000" for the line's code whenever $6E80 is
# non-zero, and $FE83 sets it on the $04 terminator -- which is every "0005"
# reply that carries a content stream, i.e. every one of ours.  So the FIRST
# record page of a session reports "000" no matter which line is chosen.  The
# $03 path clears it ($FE8B), and that is also where 目次 re-enters ($FE89 ->
# $A847), so the code only travels once the record page has been re-entered:
#
#     login -> content page -> B (目次) -> record page -> A on a line -> "013"
#
# The manual puts a date on the right of each sub-menu line (`5·1`, `5·12`).
# 22 drawn bytes is room for both, so that column is part of the title, not
# something <param> supplies -- <param> is still unexplained.
_SOFT_BULLETIN = 0x8B                       # 011 推奨ソフト速報
MENU_ENTRIES = [
    {"name": b"MARIO CLUB      ",           # 16 bytes, inline via field 2
     "items": [(content.submenu_record("013", "INLINE OK      5. 1"), 0x7F),
               (_SOFT_BULLETIN, 0x7F)]},
]

# What follows the record terminator is a HEADER, and then a content stream:
#
#     <b0> <b1> <(b1 & $0F) bytes>     header -- $87AF validates it
#     <token> <token> ...              stream -- $BCE4 walks it until $03
#
# The full derivation is in content.py's own comments.  Row 12, column 5 is
# the card's own keyboard token's
# geometry, well inside the capture-safe grid (cols 2-29, rows 3-26).
# MENU_CONTENT = None GOES STRAIGHT TO THE MENU.  $FE76 dereferences the
# record's terminator and the two values are different destinations:
#
#     $04   $6E80 = 1, JMP $BC90 -> bank 5 draws the content block below
#     $03   $6E80 = 0, JSR $A847 -> the RECORD PAGE, immediately
#
# $03 cannot be sent (CPU2 cuts the block at the first one), so the way to ask
# for it is to send NO terminator: $F3F8 writes the card's own $03 one byte
# past the last byte of the block, which lands exactly where $ACDD looks.
# server.py does that whenever this is None, and refuses a trailer with it.
#
# Two reasons to prefer it.  The manual's p.14 step 9 shows the record page
# arriving directly after the PIN, with no content page in front -- so this is
# what the real service sent.  And $6E80 stays 0, so the FIRST sub-menu
# selection already carries its own section code instead of "000".
#
# Set this to a content block instead to get the old behavior: a page after the
# PIN, with the menu one 目次 press behind it.
MENU_CONTENT = None


# -------------------------------------------------------------- the "13" page
#
# The page the '1' family's "13" command gets back.  Pressing a key on the menu
# sends `'1' "000" "13" "0000" <payload>` (bank 2 $B326 -> $F374), and bank 6
# $A03C sends every reply that is not one of its four special sub-codes to
# bank 5 $8000 -> $80B7 -- the same header + token stream as the "0005"
# trailer, with no $AC67 record in front of it.  So this is MENU_CONTENT's
# format exactly, and content.py validates it with the same ROM routines.
#
# Header $82 $80: b0's high nibble must not be $A0 (that is "hang up" at $8000)
# and its low nibble must be < 4 for $87AF; b1 = $80 takes the no-extra-bytes
# branch.  Neither byte is inert, and this is where the page's buttons live:
#
#   b0 & $03  what 目次 (the B button, $82 == $45) does -- bank 5 $9EC8's
#             jump table.  0 = nothing; 1 = BACK TO THE MENU; 2 = re-request
#             "13" with the 通信中 animation; 3 = without it.
#
#             1 is what the key is actually for -- 目次 is "table of contents".
#             $9FB8 sets $BE = 0, the pass dispatcher at $8048 sends 0 to
#             $806C, $EBD1 fades the palette and $FEA0 selects bank 6 and
#             re-enters $FE89 -> $A847, the record-page draw.  It does NOT
#             hang up: teardown is $805F, which sets $48 = $C0 first, and this
#             path does not.
#
#             $82 gives 2 instead, so on the bench 目次 asks for this page
#             again and we answer with whatever this file says by then --
#             which is what makes B a reload button, and what makes EXPERIMENT
#             above work.  A page cannot have both: b0 & $03 is one setting.
#   b1        what 実行 (the A button, $82 == $42) does -- $9EDF returns at
#             once when b1 & $0F is 0 or its high nibble is $80, so $80 makes
#             EXECUTE inert.  $9x/$Ax with n action bytes ($80-$89) behind it
#             is the live form; what they select is NOT decoded, so leave it.
#
# Confirmed on hardware 2026-08-08, serve12: two 目次 presses, two pages drawn.
PAGE13_B0, PAGE13_B1 = 0x82, 0x80

# The row band the experiments draw in.  cols 2-29 / rows 3-26 is what the
# capture rig can see (fcns-capture-overscan); everything below stays inside it.
COL = 5

# THE BUDGET.  One block is spent three times over:
#
#     252            CPU2's $8F caps a block
#    - 10            frame.build_header
#    -  3            checksum + ETX
#    - 10            build_page_reply's code + sub + spare, in FRONT of us
#     ---
#     229            what a ONE-BLOCK content page may be
#
# Past that, frame.build_page_blocks() splits the page and the card reassembles
# it at $6100 -- 2048 bytes in all before $EF53 says 4703.  That works on
# hardware, and a boundary may fall anywhere, so this is a soft ceiling now;
# the checker below still reports the block count, because how many blocks a
# page costs is worth knowing.  A
# text token costs 8 bytes of header + the text + 2 for the $5C $FE marker;
# a $A0 costs 6 + text + 2.  Latin text is ONE BYTE A CHARACTER and so is
# half-width kana, except that ﾞ and ﾟ are a second byte -- ﾍﾟｰｼﾞ is five --
# which is why the English rewrite of these pages cost bytes rather than
# saving them.  `server.py --check` reports the size and refuses an over-long
# page before it ever reaches the wire.


def _line(text, row, col=COL, width=24, cond=1):
    return content.text_token(text, col=col, row=row, width=width, cond=cond)


# ============================================================ "panes"
#
# A page can hold more than one screenful and ◀ / ▶ turn them.  byte[1] of each
# token is the pane it belongs to; $C3 is the count, $B8 the pane on screen.
# The four condition forms, all exercised here:
#
#     content.PANE(n)        only on pane n
#     content.PANE_ALWAYS    on every pane
#     content.PANE_NOT_FIRST on pane 2 and up
#     content.PANE_SEEN_LAST once the last pane has been reached -- a one-way
#                            latch, so it then shows on pane 1 as well
#
# The ◀▶ box the card draws top-left is its own ($9092), suppressed when there
# is only one pane.
_PANE_BODY = (("PANE 1: RED", "SHEET 1"),
              ("PANE 2: BLUE", "SHEET 2"),
              ("PANE 3: GREEN", "SHEET 3"))


def _panes():
    body = b"".join(
        _line(a, row=12, cond=content.PANE(n + 1))
        + _line(b, row=14, cond=content.PANE(n + 1))
        for n, (a, b) in enumerate(_PANE_BODY))
    return content.build_content(
        _line("PANE TEST GEN 8", row=8, cond=content.PANE_ALWAYS)
        + body
        + _line(">> NOT 1ST", row=18, cond=content.PANE_NOT_FIRST)
        + _line("SEEN END", row=20, cond=content.PANE_SEEN_LAST)
        + _line("< > = PREV/NEXT", row=24, cond=content.PANE_ALWAYS)
        + _line("B = RELOAD", row=26, cond=content.PANE_ALWAYS),
        b0=PAGE13_B0, b1=PAGE13_B1)


# ============================================================ "switch"
#
# `(` flavor 2, mode `$An`: a type-3 field that the `#` key cycles.  Only the
# selected child is drawn, so the three share a row on purpose -- the opposite
# of the flavor-0 cycler, where overlap is what hides the widget.  `#` is caught
# by $9B08 ahead of the field dispatcher, so it works with no cursor on the page
# at all, and a page can hold only one switch.
def _switch():
    kids = [_line(s, row=14, col=12, width=12)
            for s in ("RED", "BLUE", "GREEN")]
    return content.build_content(
        _line("SWITCH TEST GEN 8", row=10)
        + _line("COLOR:", row=14, width=6)
        + content.switch_group(kids, selected=1)
        + _line("# = TOGGLE", row=18)
        + _line("B = RELOAD", row=24),
        b0=PAGE13_B0, b1=PAGE13_B1)


# ============================================================ "container"
#
# The three containers that are NOT the flavor-0 cycler, on separate row bands
# so the cursor map ($71BA, keyed by row) can reach them:
#
#   `<` ... `>`   type 1.  A CHECKBOX GROUP, not a chooser: $856F seeds byte[7]
#                 = 0 and $8583 recurses into the children as sub-fields, so
#                 each child carries its own state.  A toggles the one under the
#                 cursor, C ($44) clears the group ($9C8C), and the submit emits
#                 one 'N'/'Y' per child -- serve16 sent `1YY` with both checked.
#   `{` ... `}`   type 7.  Cycled by `*` ($2A), a global key like `#`: $9DFA ->
#                 $9E58 finds the descriptor whose byte[3] is $07, steps byte[7]
#                 against byte[6] with wrap and redraws that child in place.
#                 $8CA1's "only the first child" is the initial state.
#                 $9E58 resolves through $9343, which matches on byte[1] == $B9
#                 -- the CURSOR'S ROW -- so a `{}` is only reachable when it
#                 shares a row with a field that is in the cursor map.  It has
#                 no slot of its own ($96B6 skips byte[3] == $07).
#   `(` $B0       type 6.  Left/Right as well, but no C, and its marker is the
#                 four-sprite bracket ($92B1) rather than per-child boxes.
#
# CHILDREN GO SIDE BY SIDE, NOT STACKED.  The markers are sprites: $9273 puts a
# box at (col-1, row) for each child and $9244 puts the selection pointer at
# (col-1, row+1) for the chosen one.  Stack the children on consecutive rows and
# the pointer lands on the next child's box.
def _container():
    def kids(row, *labels):
        return [_line(s, row=row, col=12 + i * 6, width=5)
                for i, s in enumerate(labels)]

    # The `{}` shares row 12 with the `<>` so that $B9 can resolve it: both
    # register byte[1] = $8C, instance 1 and 2, and $9E58 walks from one to the
    # other.  Its two children share a column -- only one is ever drawn.
    #
    # b1 = $93 makes EXECUTE (A) LIVE, which is what checks a checkbox: $9EDF
    # needs b1 & $0F non-zero and a high nibble that is not $80, then dispatches
    # on the current field's type -- type 1 toggles the box at byte[7]+7.  The
    # low nibble must NOT be 1, or $9F02 takes the page-level branch instead.
    #
    # The action bytes are read only on the type-6 path, which indexes them by
    # the selection -- hence one per (B0) option.  NO ACTION BYTE IS INERT: $80
    # resets every field on the page ($9678 -> $95B1), which wipes the very
    # checkboxes this page is demonstrating.  $82 is the untraced one and the
    # worst it does is re-request the page.
    return content.build_content(
        _line("CONTAINER TEST GEN 8", row=8)
        + _line("<>{}:", row=12, width=8)
        + content.angle_group(kids(12, "RED", "BLUE"))
        + content.brace_group([_line(s, row=12, col=24, width=5)
                               for s in ("ON", "OFF")])
        + _line("(B0):", row=20, width=8)
        + content.group(kids(20, "HIGH", "LOW", "MID"), b1=0xB0)
        + _line("A = CHECK  * = {}", row=24)
        + _line("B = RELOAD", row=26),
        b0=PAGE13_B0, b1=0x93, extra=b"\x82\x82\x82")


# ============================================================ "flavor1"
#
# `(` flavor 1, modes `$90` and `$91` -- the one flavor that registers a field
# PER CHILD ($834B / $83B9): type 4 for $90 (stride 6), type 8 for $91 (stride
# 8).  Both key handlers are $9DB3, a bare RTS, so neither takes a keypress.
#
# Each child's byte[1] also feeds $CE ($8395/$8407), which $810C folds into the
# pane count -- so this is the ROM's paged list, one child per pane, and it
# reaches the pane mechanism without any token declaring a pane above 1.
#
# Keys to try: ▶ and ◀.
def _flavor1():
    kids = [_line(s, row=14, col=12, width=12, cond=content.PANE(n + 1))
            for n, s in enumerate(("CHILD 1", "CHILD 2", "CHILD 3"))]
    return content.build_content(
        _line("FLAVOR 1 TEST GEN 8", row=10)
        + content.group(kids, b1=0x90)
        + _line("< > = PREV/NEXT", row=18)
        + _line("B = RELOAD", row=24),
        b0=PAGE13_B0, b1=PAGE13_B1)


# ============================================================ "form"
#
# Two `;`-separated option cyclers (flavor 0, type 5): Left/Right steps the
# selection of whichever one holds the cursor, Up/Down moves between them, and
# `b1 & $0F` is each group's own initial choice.  Two constraints on the layout:
#
#   * Every alternative of a group is DRAWN ($8D55 walks the whole group), so
#     alternatives sharing a column and row overwrite each other and the cycler
#     reads as a single label.  One row per alternative here.
#   * Widgets are addressed BY SCREEN ROW -- $71BA is a 29-slot cursor map keyed
#     on the row a field's first alternative sits on, and $9BC7 walks it for the
#     next populated slot on Up/Down.  Two fields on one row collapse to a
#     single reachable one.
#
# No $F1 cursor record is needed.
FORM_OPTIONS = ("RED     ", "BLUE    ", "GREEN   ")
FORM_OPTIONS2 = ("ON ", "OFF")
_FORM_ROWS = (14, 16, 18)


def _form():
    alts = [[_line(o, row=r, col=12, width=8)]
            for o, r in zip(FORM_OPTIONS, _FORM_ROWS)]
    alts2 = [[_line(o, row=r, col=12, width=4)]
             for o, r in zip(FORM_OPTIONS2, (20, 22))]
    return content.build_content(
        _line("UP DOWN TEST GEN 8", row=12)
        + _line("COLOR:", row=14, width=6)
        + content.option_group(alts, selected=3)
        + _line("SWITCH:", row=20, width=7)
        + content.option_group(alts2, selected=2)
        + _line("B = RELOAD", row=24)
        + _line("UP DOWN TO MOVE ?", row=26),
        b0=PAGE13_B0, b1=PAGE13_B1)


# ============================================================ "echo"
#
# The round trip: a form whose submitted value comes back on the next page.
#
# $98A8 puts the whole form in the request payload -- '0' at $600A overwritten
# by the type-6 field's selection, then one 'N'/'Y' per `<>` checkbox -- so
# `req["payload"]` is the state of the widgets below.
#
# To submit: A on the `<>` row toggles a box; A on the `(B0)` row fires action
# byte $82, which re-requests the page and carries the form with it.
def _echo(req):
    sent = req["payload"] if req else b""
    try:
        shown = sent.decode("ascii")
    except UnicodeDecodeError:
        shown = sent.hex()
    return content.build_content(
        _line("ECHO TEST GEN 8", row=8)
        + _line("SENT: " + (shown or "-"), row=10)
        + _line("<> :", row=14, width=8)
        + content.angle_group([_line(s, row=14, col=12 + i * 6, width=5)
                               for i, s in enumerate(("RED", "BLUE"))])
        + _line("(B0):", row=18, width=8)
        + content.group([_line(s, row=18, col=12 + i * 6, width=5)
                         for i, s in enumerate(("HIGH", "LOW", "MID"))], b1=0xB0)
        + _line("A = CHECK / SEND", row=22)
        + _line("B = RELOAD", row=24),
        b0=PAGE13_B0, b1=0x93, extra=b"\x82\x82\x82")


# ============================================================ "para"
#
# The `$A0` paragraph token: prose that WRAPS and PAGINATES ITSELF.
#
# Every page above lays text out by hand, one `$80` per line, because that is
# the only token whose header was decoded.  `$A0` is the one that flows: six
# header bytes carry column, row, width, height and style, and `$ACE4` breaks
# the text into lines at the width.  When it runs past the height its own pane
# counter `$AF` advances, `$8995` folds that into `$C3`, and ◀ ▶ turn the
# overflow -- so a paragraph too long for the screen becomes a multi-pane page
# with no per-token conditions at all.
#
# THE CARD'S WRAP IS NOT WORD-AWARE.  `$AF24` re-saves the position before
# every character, so the line breaks exactly at the width -- mid-word, and in
# kana between a character and a following ﾞ/ﾟ, which JIS X 0201 makes a
# character of its own.  The card cannot be told otherwise, so `wrap=True` has
# content.wrapped() pre-break the text at word boundaries with `$5C $F0`.  That
# costs two bytes a line, which is the whole price of readable prose.
#
# An `$A0` has NO draw condition (`$8CB9` draws any `$Ax`), so the headings
# around it are `$80`s with PANE_ALWAYS; a plain PANE(1) heading would vanish
# the moment the paragraph turned the page.
#
# The escapes `$ACE4` honors inside the text are content.py's: `$5C $F0` is a
# line break, `$5C $3C` / `$5C $3E` bracket an emphasized run.  Only `$5C $FE`
# is required, and para_token() insists on it.
_PARA_TEXT = ("WELCOME TO MARIO CLUB. THIS PARAGRAPH TESTS WORD WRAP AND "
              "PAGE TURNS. WHEN THE TEXT RUNS PAST THE HEIGHT IT GOES ON "
              "TO THE NEXT PANE.")


def _para():
    return content.build_content(
        _line("PARA TEST GEN 8", row=6, cond=content.PANE_ALWAYS)
        + content.para_token(_PARA_TEXT, col=4, row=9, width=23, height=5,
                             wrap=True)
        + _line("< > = PREV/NEXT", row=24, cond=content.PANE_ALWAYS)
        + _line("B = RELOAD", row=26, cond=content.PANE_ALWAYS),
        b0=PAGE13_B0, b1=PAGE13_B1)


# ============================================================ "split"
#
# A page too big for one block: 448B out as [252B '1' '0'] and [232B '3' '1'],
# reassembled by the card at $6100.
#
# `$EF32` appends each block at `$6E29`/`$6E2A` and only after the LAST one
# does `$F3F8` write the stream's `$03`.  So there is no partial draw: either
# every block landed and this renders, or bank 5 walks a truncated stream and
# the screen shows a four-digit error.  The last line below is the last token
# in the stream, which is why it is the one that proves the final block landed.
#
# The boundary lands at content byte 229 -- mid-word, inside the $A0's text --
# and draws correctly, so a split really may fall anywhere.  The blocks go out
# server.BLOCK_GAP apart; back-to-back has not been tried.
_SPLIT_TEXT = (
    "THIS PAGE DOES NOT FIT IN ONE BLOCK. CPU2 CAPS A BLOCK AT 252 BYTES AND "
    "TEN OF THEM ARE THE HEADER, SO THE SERVER CUTS THE PAGE UP AND THE CARD "
    "PUTS IT BACK TOGETHER AT 6100. EACH BLOCK IS APPENDED AT THE RUNNING "
    "POINTER AND NOTHING READS THE BYTES UNTIL THE TERMINATOR ARRIVES AFTER "
    "THE LAST ONE, SO A BOUNDARY MAY FALL ANYWHERE.")


def _split():
    return content.build_content(
        _line("SPLIT TEST GEN 8", row=4, cond=content.PANE_ALWAYS)
        + content.para_token(_SPLIT_TEXT, col=4, row=7, width=23, height=7,
                             wrap=True)
        + _line("< > = PREV/NEXT", row=22, cond=content.PANE_ALWAYS)
        + _line("B = RELOAD", row=24, cond=content.PANE_ALWAYS)
        # The last token in the stream: it draws only if the final block landed.
        + _line("LAST BLOCK OK", row=26, cond=content.PANE_ALWAYS),
        b0=PAGE13_B0, b1=PAGE13_B1)


# ============================================================ "input"
#
# The type-2 field -- the last widget with no page behind it.  `$C0` is a text
# entry and `$C1` a numeric one; `$824D` -> `$85C4` registers type 2 for both
# and `$9C9B` -> `$A25C` is the editor.  content.py has the derivation.
#
# Two of them, on rows of their own so `$71BA` can reach both, plus a
# (B0) cycler to drive EXECUTE the way "echo" does.  The keys:
#
#   .        on the TEXT field, opens the ON-SCREEN KEYBOARD -- $A3FF draws the
#            $930E record, sets $C6 = 1 and re-walks the stream.  Bank 5's own
#            $BB23/$BB83 tokens are that keyboard's key labels, which is what
#            they were always for.  おわり puts the assembled string back in the
#            field, and it goes out with the form like any other type-2 value.
#   digits   go straight into either field, right to left ($A343 shifts the
#            value left and writes the new one at the end, like a calculator)
#   .        on the NUM field moves to the fraction ($C7 = 1), since it
#            declares two decimal places
#   C        clears the field the cursor is on ($A37B)
#   A        submits.  $98A8's type-2 arm is $9950, and it serializes the raw
#            value with its fill: serve20 sent `1ABCD     12323` -- the (B0)
#            selection, then the 8-wide text field, then the 4+2 number.
def _input(req):
    sent = req["payload"] if req else b""
    try:
        shown = sent.decode("ascii")
    except UnicodeDecodeError:
        shown = sent.hex()
    return content.build_content(
        _line("INPUT TEST GEN 8", row=8)
        + _line("SENT: " + (shown or "-"), row=10)
        # fill = 0 explicitly: canonical slot 9 bit 6 is the MASK, and $B227 /
        # $B256 would replace the value with `&` ($26, a key on the keyboard).
        # Spelled out here because this page is about what a field shows.
        + _line("TEXT:", row=14, width=6)
        + content.input_token(8, col=12, row=14, fill=0)
        + _line("NUM:", row=18, width=5)
        + content.number_token(4, 2, col=12, row=18, fill=0)
        + content.group([_line(s, row=20, col=12 + i * 6, width=5)
                         for i, s in enumerate(("SEND", "WAIT"))], b1=0xB0)
        + _line(". = KEYBOARD  C = CLR", row=22)
        + _line("A = SEND / B = RELOAD", row=24),
        b0=PAGE13_B0, b1=0x93, extra=b"\x82\x82\x82")


# ============================================================ "menu"
#
# `b0 & $03 = 1`: 目次 goes BACK TO THE MENU instead of re-requesting this page.
# $9FB8 -> $BE = 0 -> $806C -> $EBD1 fades -> $FEA0 -> bank 6 $FE89 -> $A847,
# the record-page draw.  The record the "0005" reply carried is still in W-RAM,
# so the card redraws the menu it was given at login.
#
# THIS PAGE HAS NO RELOAD.  b0 & $03 is one setting and this spends it on 目次,
# so B leaves rather than re-reading page.py.  Getting back depends on what the
# menu sends when a line is chosen -- which is the undecoded part,
# and watching the log for that request is half the point of this page.  If
# nothing comes back, redial.
def _menu():
    return content.build_content(
        _line("MENU RETURN GEN 8", row=10)
        + _line("B = MOKUJI -> MENU", row=14)
        + _line("NOT A RELOAD AND NOT", row=18)
        + _line("A HANGUP: $806C, NOT", row=20)
        + _line("$805F.", row=22),
        b0=(PAGE13_B0 & 0xFC) | 1, b1=PAGE13_B1)


# ============================================================ "probe"
#
# Draws the request that asked for it.  `b0 & $03 = 1` so 目次 goes back to the
# record page, which makes the whole loop one page file:
#
#     probe  --B-->  record page  --D-pad + A-->  probe, showing what was sent
#
# So picking a sub-menu line displays that line's own request, and the card
# documents its own navigation without anyone reading a log.  The request's
# `'1' <section:3> <command:2> <spare:4> <payload>` layout.
def _probe(req):
    if req is None:
        sec, cmd, spare, pay = b"---", b"--", b"----", b""
    else:
        sec, cmd = req["section"], req["command"]
        spare, pay = req["spare"], req["payload"]

    def txt(b):
        return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b) or "-"

    return content.build_content(
        _line("PROBE GEN 8", row=6)
        + _line("SECTION : " + txt(sec), row=10)
        + _line("COMMAND : " + txt(cmd), row=12)
        + _line("SPARE   : " + txt(spare), row=14)
        + _line("PAYLOAD : " + txt(pay)[:14], row=16)
        + _line("HEX: " + pay[:8].hex(" "), row=18)
        + _line("B = MOKUJI -> MENU", row=24),
        b0=(PAGE13_B0 & 0xFC) | 1, b1=PAGE13_B1)


# ============================================================ "pageact"
#
# PROBE P1, the site's whole interaction model on one page: a flavor-0 cycler
# list plus PAGE-LEVEL EXECUTE.  b1 = $91 low nibble 1 takes $9EDF's $9F6D
# branch -- action byte = $610C, our $83, a re-request carrying the form --
# WITHOUT dispatching on the current field, so the untraced $F9AF arm is never
# reached.  $83 itself has not been fired on hardware; $82 (proven) is one
# byte away if this hangs.  Expected on A: a "13" request with payload '0' +
# the cycler's digit, echoed below.  site_page.py serves nothing until this
# passes.
def _pageact(req):
    pay = req["payload"] if req else b""
    shown = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in pay) or "-"
    alts = [[_line(s, row=12 + i * 2, col=6, width=14)]
            for i, s in enumerate(("LINE ONE", "LINE TWO", "LINE THREE"))]
    return content.build_content(
        _line("PAGEACT GEN 8", row=6)
        + _line("SENT: " + shown[:16], row=8)
        + content.option_group(alts, selected=1)
        + _line("<> PICK  A = $83", row=22)
        + _line("B = RELOAD", row=24),
        b0=PAGE13_B0, b1=0x91, extra=b"\x83")


# These run on the card.  The only marker worth carrying is the other one.
EXPERIMENTS = {
    "panes":     _panes,       # ◀ ▶ turn pages
    "switch":    _switch,      # `#` cycles a $An switch
    "form":      _form,        # two option cyclers
    "container": _container,   # <> {} ( $B0 ), A, C, *
    "echo":      _echo,        # draws back what was submitted
    "flavor1":   _flavor1,     # ( $90 ), one field per child
    "para":      _para,        # $A0, wraps and paginates
    "split":     _split,       # >1 block, reassembled at $6100
    "input":     _input,       # $C0 + $C1 type-2 fields
    "menu":      _menu,        # b0 & $03 = 1, 目次 returns
    "probe":     _probe,       # draws the request that asked for it
    "pageact":   _pageact,     # P1: page-level EXECUTE, action $83
}

# What page(None) must measure as.  Read this as "does some alternative carry a
# nested-bracket sub-field", NOT as "do the widgets work" -- an interactive=False
# page cycles fine (2026-08-09).  The loader refuses a page that disagrees with
# this because the True shape is the one that hung the card.
# Set to None to skip the guard.  Every experiment above is False.
INTERACTIVE = False


def page(req):
    """The content block for one "13" page request.

    `req` is frame.split_request(data) -- {"section", "command", "spare",
    "payload"} as bytes -- or **None**, which is the loader's preview call at
    save time.  Return a representative page for None; do not return None.

    `req["section"]` is the three digits the card asks for; `req["payload"]` is
    `'M'` for a plain 目次 and **the serialized form** for anything else.
    A builder that wants it declares a parameter; the rest are called bare.
    """
    try:
        build = EXPERIMENTS[EXPERIMENT]
    except KeyError:
        raise ValueError("EXPERIMENT = %r is not one of %s"
                         % (EXPERIMENT, ", ".join(EXPERIMENTS)))
    return _build(build, req)


def _build(fn, req):
    return fn(req) if fn.__code__.co_argcount else fn()


if __name__ == "__main__":
    # `server.py --check` only ever sees the ONE experiment EXPERIMENT names.
    # Running this file runs the card's own $88D0 walk and $80B7 measure pass
    # over ALL of them, so a bench call can flip the dial without discovering
    # at the wire that the next page down the list was malformed.
    print(f"login   {LOGIN_MESSAGE!r} key {LOGIN_KEY!r}")
    print(f"menu    {len(MENU_ENTRIES)} entr(ies), content "
          + (MENU_CONTENT.hex(" ") if MENU_CONTENT is not None
             else "none -- unterminated, straight to the record page"))
    import frame                      # the checker's, not the page's
    card = content.checker()
    bad = 0
    for name, build in EXPERIMENTS.items():
        mark = "->" if name == EXPERIMENT else "  "
        try:
            blk = _build(build, None)
        except Exception as exc:                        # noqa: BLE001
            bad += 1
            print(f"{mark} {name:<10} BUILD FAILED: {exc}")
            continue
        chk = card.check_content(blk)
        m = card.measure(blk)
        why = chk["error"] or m["error"]
        size = f"{len(blk)}B"
        try:
            n = len(frame.build_page_blocks(blk))
        except ValueError as exc:                       # past $EF53's ceiling
            n, why = 0, str(exc)
        if n > 1:
            size += f"/{n}blk"
        if why:
            bad += 1
        if m["modeled"]:
            fields = ",".join("t%d" % f["type"] if f["kind"] == "field"
                              else f["kind"] for f in m["fields"]) or "-"
            panes = f"panes={m['c3'] & 0x7F}" + (
                " (sole)" if m["c3"] & 0x80 else "       ")
        else:
            fields, panes = "(needs a ROM)", "panes=?       "
        print(f"{mark} {name:<10} {size:>9}  {panes}"
              f"  fields={fields:<16} {why or 'ok'}")
    print("run `python3 server.py --check` for the served one in full")
    sys.exit(1 if bad else 0)
