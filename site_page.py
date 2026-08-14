#!/usr/bin/env python3
"""THE SITE: a JSON page tree in site/, served via --page site_page.py.

The manual's whole service as data: site.json names the menu (each line a
3-digit section code and a target node), pages/**/*.json are the nodes, and
games/publishers/stores.json are the databases the query lists draw from.
server.py re-execs this module whenever any watched file moves (WATCH below),
so a JSON edit reloads mid-call; SESSION_STATE is carried across reloads.

ROUTING.  A menu selection arrives as a
1-byte payload with the line's section code; everything deeper is a form
submit on whatever node SESSION_STATE says is on screen.  Every interactive
page here uses page-level EXECUTE (b1 $91, action $83) and flavor-0 option
cyclers only, so a submit is always '0' plus at least one selection digit --
never 1 byte, which is what keeps the two request kinds distinguishable.
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import content  # noqa: E402
import frame    # noqa: E402

SITE_DIR = os.path.join(HERE, "site")
WATCH = [os.path.join(SITE_DIR, "**", "*.json")]

# One interaction shape for every page.  B (目次): $81 -> the record page from
# W-RAM, no request; $82 -> re-request with 'M' (the router pops), and $6E47 = 0
# so the 通信中 screen keeps its Mario animation ($83 is the same request with
# the animation suppressed).  A (実行): $91 takes the page-level branch to the
# action byte, a re-request carrying the form.
B0_MENU, B0_PARENT = 0x81, 0x82
B1_FORM, B1_LEAF = 0x91, 0x80

COL = 4                      # the card's border owns cols 0-1 and 30-31
# The field cursor is four sprites at a HARDCODED x = 12..27 ($A247), whatever
# column the field is in, so a list row must start at column 4 to clear it.
LIST_COL = 4
# The indent is the cursor's, so a page without one does not pay it: the real
# service drew a record page hard against the border, two columns left of its
# own ◆ (supp. p.4 photo).  Every non-interactive renderer uses these.
TEXT_COL = 2
TEXT_WIDTH = 27                         # cols 2..28
PROSE_COL = TEXT_COL + 1                # the guide page's own leading space,
                                        # which its ・ bullets hang off (supp. p.2)
VALUE_COL = TEXT_COL + 10               # clear of the longest label
VALUE_CELLS = 29 - VALUE_COL            # a record's value column runs to 28
ROW_TITLE = 3
# A title is bracketed by ◆, as bank 1's own are ($967D) and as the manual
# draws every page (p.10, supp. p.2, p.3): two full-width glyphs, two cells
# each.  The left one clears columns 2-3, which is where $9092 paints the card's
# own ◀▶ box, so it is drawn whether or not the page has panes.
DIAMOND = "◆"
DIA_COL_L = 4
DIA_COL_R = 28
TITLE_COL = DIA_COL_L + 2
TITLE_CELLS = DIA_COL_R - TITLE_COL     # cols 6..27
ROW_FIRST = 6
ROW_HINT = 26
LINE_STEP = 2                # a plain line is two tile rows (ROW_STYLE below)
ROW_LAST = ROW_HINT + LINE_STEP - 1     # the last row a line may reach
MAX_LIST = 9                 # option rows 6..22; longer lists get NEXT PAGE
WIDTH = 25                   # cols 4..28
LABEL_CELLS = 29 - LIST_COL + 1         # a list row runs to the border
DATE_CELLS = 5                          # `11/21`; a 6th would hit the top mark
TOP_MARK = "✌"               # card tile $02, the V-sign the supplement (p.2)
                             # put in place of the `*` on a top pick


def _load(name):
    with open(os.path.join(SITE_DIR, name), encoding="utf-8") as f:
        return json.load(f)


SITE = _load("site.json")
GAMES = _load("games.json")
PUBLISHERS = _load("publishers.json")
STORES = _load("stores.json")

LOGIN_MESSAGE = SITE["login"]
LOGIN_KEY = SITE["login_key"].encode("ascii")
REJECT_MESSAGE = SITE["reject"]
INTERACTIVE = False

# The page-level action byte.  $83 by default; "action_byte": "82" in
# site.json swaps in the hardware-proven neighbor if probe P1 faults on $83.
ACTION = bytes.fromhex(SITE.get("options", {}).get("action_byte", "83"))
if not 0x80 <= ACTION[0] <= 0x89:
    raise ValueError("action_byte must be 80..89 ($87AF's range)")

# How a list draws its rows.  "cursor" is the manual's own shape (p.10, p.16):
# flavor 1 ($90) registers ONE type-4 field PER ROW, so each row owns a $71BA
# slot and Up/Down walks the ➡ between them ($9BC7).  Types 4 and 8 dispatch to
# $915C -- a bare RTS -- in $912D's marker table, so no bracket is drawn and the
# field cursor is the only marker, exactly as the manual shows.
#
# "cycler" is the fallback: flavor 0, one type-5 field for the whole list,
# stepped Left/Right with $92B1's bracket around the selection AND the field
# cursor pinned to the anchor row -- two markers, one of them redundant.
LIST_STYLE = SITE.get("options", {}).get("list_style", "cursor")
if LIST_STYLE not in ("cursor", "cycler"):
    raise ValueError('list_style is "cursor" or "cycler"')

# Canonical slot 8, byte[5] of a `$80` token.  The card's native text is the
# 16 px-tall glyph -- two tile rows per line, which is what the manual draws
# everywhere and what the 16 px field cursor ($A205) is sized for.  Narrow is
# bank 5's own internal style, not a page style, so nothing here uses it.
ROW_STYLE = content.STYLE_PLAIN
PARA_HEIGHT = ROW_HINT - ROW_FIRST      # $A0 slot 7 counts TILE ROWS, so this
                                        # is PARA_HEIGHT/LINE_STEP plain lines

# Slot 8 bits $60 pick which CHR bit plane the glyph is written into, not a
# palette: $AF0B indexes $AF07 = `40 40 C0 80` into $53, and $D92F writes plane 0
# for bit $40 and plane 1 for bit $80.  The screen is BG palette 0 throughout
# ($C950 fills the attribute table with 0), and on a content page that palette is
# $EC90 = `0F 30 21 25`, so the pixel value IS the color: index 0/1 white, index 3
# light azure, index 2 light rose.
# Emphasis is not a fourth color: $DA96 inverts the glyph's rows before the plane
# is chosen, so it is reverse video in whatever color the token already had.
TITLE_PALETTE = SITE.get("options", {}).get("title_palette", 3)
TITLE_EMPHASIS = SITE.get("options", {}).get("title_emphasis", True)
HIT_PALETTE = SITE.get("options", {}).get("hit_palette", 2)
for _n, _v in (("title_palette", TITLE_PALETTE), ("hit_palette", HIT_PALETTE)):
    if _v not in (0, 1, 2, 3):
        raise ValueError(f"{_n} indexes $AF07, so it is 0..3")
EMPH = content.STYLE_EMPHASIS

SESSION_STATE = {"node": None, "stack": [], "quest": {}, "results": None}


# ------------------------------------------------------------------ the menu

def _menu():
    entries, codes = [], {}
    for ent in SITE["menu"]:
        name = ent["name"].encode("ascii")
        if len(name) > 16:
            raise ValueError(f"menu name {ent['name']!r} is over 16 bytes")
        items = []
        for line in ent["lines"]:
            items.append((content.submenu_record(line["code"], line["title"]),
                          0x7F))
            codes[line["code"]] = line["goto"]
        entries.append({"name": name.ljust(16), "items": items})
    return entries, codes


MENU_ENTRIES, MENU_CODES = _menu()


# ------------------------------------------------------------------ the nodes

def _load_nodes():
    nodes = {}
    root = os.path.join(SITE_DIR, "pages")
    for path in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
        nid = os.path.relpath(path, root)[:-5].replace(os.sep, "/")
        with open(path, encoding="utf-8") as f:
            nodes[nid] = json.load(f)
    return nodes


def _game_label(gid, g):
    day = str(g.get("day", "TBD"))
    # The supplement's screens date with a slash, not a dot.
    date = f"{g['month']}/{day:>2}" if day.isdigit() else f"{g['month']}/{day}"
    if len(date) > DATE_CELLS:
        raise ValueError(f"date {date!r} is {len(date)} cells, {DATE_CELLS} fit "
                         f"-- it would run into the top-pick mark ({gid})")
    mark = TOP_MARK if g.get("top") else " "
    # The hardware label is ONE glyph on this card, not two letters ($8541 and
    # friends), so the label is assembled as bytes; the JSON keeps `"hw": "SF"`.
    # A 5-wide date column, so the title keeps 17 cells; only `5.LATE` is wider
    # and pushes its own row along by one.
    # Right-justified, so a one-digit month lines its slash up with a two-digit
    # one (supp. p.3).  `5/MID` and `5/TBD` already fill the column and stay put.
    head = content.halfwidth(f"{date:>{DATE_CELLS}}{mark}", terminate=False)
    hw = content.HW.get(g["hw"]) or content.halfwidth(g["hw"], terminate=False)
    # `short` is the row's name where the real one does not fit; the detail
    # page and the title search both keep using `title`.
    tail = content.halfwidth(" " + g.get("short", g["title"]), terminate=False)
    row = content.cells(head) + content.cells(hw) + content.cells(tail)
    if row > LABEL_CELLS:
        raise ValueError(
            f"{gid}: {g.get('short', g['title'])!r} is {row - LABEL_CELLS} "
            f"cell(s) over the row -- give the game a shorter \"short\"")
    return head + hw + tail


def _game_sort(g):
    day = str(g.get("day", "TBD"))
    late = {"MID": 40, "LATE": 50, "TBD": 60}
    return (int(g["month"]), int(day) if day.isdigit() else late.get(day, 70))


def _match(g, k, v):
    if k == "month_from":
        return int(g["month"]) >= int(v)
    return g.get(k) == v


def _query_items(q, back_catalog=False, goto="game/{gid}", newest_first=False):
    # db_only marks back-catalog titles: in the database (search), off the
    # release calendars.
    got = [(gid, g) for gid, g in GAMES.items()
           if (back_catalog or not g.get("db_only"))
           and all(_match(g, k, v) for k, v in q.items() if k != "db")]
    # Stable either way, so a same-day tie keeps games.json's order.
    got.sort(key=lambda p: _game_sort(p[1]), reverse=newest_first)
    # `text` is what the title search matches on -- `label` is bytes now.
    return [{"label": _game_label(gid, g), "text": g["title"],
             "goto": goto.format(gid=gid), "hit": bool(g.get("top"))}
            for gid, g in got]


def _rating_node(g):
    """A top pick's VR Game Report page, from the game's own `rating` block."""
    r = g["rating"]
    body = "\n".join(f"{name:<12}{score}" for name, score in r["scores"])
    return {"type": "prose", "title": g["title"], "back": "parent",
            "body": f"Member ratings of a top pick.\n\n{body}\n\n"
                    f"From {r['replies']} member replies."}


def _place(i):
    """(pane, row) for item i of a list -- MAX_LIST rows to a pane.

    Panes are client-side: ◀ ▶ (前ページ/次ページ) turn them with no request,
    the card draws its own indicator at columns 2-3, row 3, and rows are reused
    on every pane because `$9343` runs each candidate descriptor through
    `$8DB2` before matching a row, so only the pane on screen resolves.
    """
    return i // MAX_LIST + 1, ROW_FIRST + (i % MAX_LIST) * LINE_STEP


def _expand(nodes):
    out = {}
    for nid, node in nodes.items():
        kind = node["type"]
        if kind == "list":
            if "query" in node:
                node = dict(node, items=_query_items(
                    node["query"], goto=node.get("goto", "game/{gid}"),
                    newest_first=node.get("newest_first", False)))
            if not node["items"]:
                node = dict(node, items=[{"label": "Nothing listed yet",
                                          "goto": nid, "sibling": True}])
            out[nid] = node
        elif kind == "quest-num":
            out[nid] = node
            out[nid + "@entry"] = node
        elif kind == "quest-choice":
            out[nid] = node
            out[nid + "@entry"] = node
            out[nid + "@confirm"] = node
        else:
            out[nid] = node
    for gid, g in GAMES.items():
        out.setdefault("game/" + gid, {"type": "detail", "game": gid})
        if "rating" in g:
            out.setdefault("vr/rating/" + gid, _rating_node(g))
    for pid, p in PUBLISHERS.items():
        out.setdefault("members/pub/" + pid,
                       {"type": "prose", "title": p["name"],
                        "back": "parent", "body": p["body"]})
    for sid, s in STORES.items():
        out.setdefault("retail/store/" + sid,
                       {"type": "record", "title": s["name"],
                        "back": "parent", "fields": s["fields"],
                        "panes": s.get("panes", [])})
    return out


NODES = _expand(_load_nodes())


# ----------------------------------------------------------------- rendering

def _line(text, row, col=COL, cond=1, palette=0, emph=False):
    style = ROW_STYLE | content.STYLE_PALETTE(palette) | (EMPH if emph else 0)
    body = text if isinstance(text, bytes) else content.halfwidth(text)
    # One column past the text: byte[4] carries width-1, so a field sized to the
    # exact character count wraps its last cell onto the next row (measured).
    cells = content.cells(body)
    width = cells + 1
    if col + width > 32:
        raise ValueError(f"{cells} cells at column {col} runs off the screen: "
                         f"{body[:-2].decode('ascii', 'replace')!r}")
    if row + LINE_STEP - 1 > ROW_LAST:
        raise ValueError(f"row {row} runs off the bottom (last is {ROW_LAST}): "
                         f"{body[:-2].decode('ascii', 'replace')!r}")
    return content.text_token(body, col=col, row=row, width=width, cond=cond,
                              style=style)


def _wrap_lines(text, width=WIDTH - 1):
    body = content.wrapped(text, width, terminate=False)
    return [ln + b"\x5c\xfe" for ln in body.split(b"\x5c\xf0") if ln]


def _title(node, cond=content.PANE_ALWAYS):
    """The page header: the title with a white ◆ at each end."""
    def dia(col):
        return _line(DIAMOND, ROW_TITLE, col=col, cond=cond) if DIAMOND else b""

    if content.cells(node["title"]) > TITLE_CELLS:
        raise ValueError(f"title {node['title']!r} is over {TITLE_CELLS} cells "
                         f"-- it would run into the ◆ at column {DIA_COL_R}")
    return (dia(DIA_COL_L)
            + _line(node["title"], ROW_TITLE, col=TITLE_COL, cond=cond,
                    palette=TITLE_PALETTE, emph=TITLE_EMPHASIS)
            + dia(DIA_COL_R))


def _b0(node):
    return B0_MENU if node.get("back", "parent") == "menu" else B0_PARENT


# Nothing is drawn at the bottom right: the card puts its own スーパーマリオクラブ
# badge there.  The manual's list pages carry no key prompts at all, and a
# record page carries only its `n/N` counter, bottom left.


def _buttons(labels, row, selected=1):
    """One option cycler, alternatives side by side: the [OK] [FIX] row.

    Spaced to end before column 22, where the card's own badge begins.
    """
    col, alts = COL, []
    for lab in labels:
        alts.append([_line("[" + lab + "]", row, col=col)])
        col += len(lab) + 3
    return content.option_group(alts, selected=selected)


def _page(node, tokens, interactive):
    return content.build_content(
        tokens,
        b0=_b0(node),
        b1=B1_FORM if interactive else B1_LEAF,
        extra=ACTION if interactive else b"")


def _render_list(node, ctx):
    toks = _title(node)
    rows = []
    for i, it in enumerate(node["items"]):
        pane, row = _place(i)
        rows.append(_line(content.clip(it["label"], LABEL_CELLS), row,
                          col=LIST_COL,
                          palette=HIT_PALETTE if it.get("hit") else 0,
                          cond=content.PANE(pane)))
    if LIST_STYLE == "cursor":
        toks += content.group(rows, b1=0x90)
    else:
        toks += content.option_group([[r] for r in rows], selected=1)
    return _page(node, toks, interactive=True)


def _render_record(node, ctx):
    """The labeled-fields page: game details, hardware info, store top-5s."""
    panes = node.get("panes", [])
    total = 1 + len(panes)
    cond1 = content.PANE(1) if total > 1 else 1
    toks = _title(node)
    y = ROW_FIRST
    for label, value in node["fields"]:
        toks += _line(label, y, col=TEXT_COL, cond=cond1)
        # No blank row between fields: a full-height line already separates
        # them, and seven fields plus gaps do not fit in ten line slots.
        for ln in _wrap_lines(value, VALUE_CELLS) or [content.halfwidth("")]:
            toks += _line(ln, y, col=VALUE_COL, cond=cond1)
            y += LINE_STEP
    for n, pane in enumerate(panes, start=2):
        toks += _line(pane["head"], ROW_FIRST, col=TEXT_COL,
                      cond=content.PANE(n))
        y2 = ROW_FIRST + LINE_STEP
        for ln in _wrap_lines(pane["body"], TEXT_WIDTH - 1):
            toks += _line(ln, y2, col=TEXT_COL, cond=content.PANE(n))
            y2 += LINE_STEP
    for n in range(1, total + 1):
        toks += _line(f"{n}/{total}", ROW_HINT, col=TEXT_COL,
                      cond=content.PANE(n) if total > 1 else 1)
    return _page(node, toks, interactive=False)


def _render_detail(node, ctx):
    g = GAMES[node["game"]]
    day = str(g.get("day", "TBD"))
    fields = [("Publisher:", g["publisher"]),
              ("Hardware:", g.get("spec", g["hw"])),
              ("Released:", g.get("released", f"{g['month']}.{day} '91")),
              ("Price:", g.get("price", "TBD")),
              ("Genre:", g.get("genre_name", g.get("genre", ""))),
              ("Continue:", g.get("cont", "None")),
              ("Notes:", g.get("notes", ""))]
    rec = {"type": "record",
           "title": g["title"],
           "back": node.get("back", "parent"),
           "fields": [(a, b) for a, b in fields if b],
           "panes": g.get("extra_panes", [])}
    return _render_record(rec, ctx)


def _render_prose(node, ctx):
    toks = _title(node)
    toks += content.para_token(node["body"], col=PROSE_COL, row=ROW_FIRST,
                               width=TEXT_WIDTH - 2, height=PARA_HEIGHT,
                               style=ROW_STYLE, wrap=True)
    return _page(node, toks, interactive=False)


def _render_question(node, ctx):
    toks = _title(node)
    y = ROW_FIRST
    for ln in _wrap_lines(node["question"]):
        toks += _line(ln, y)
        y += LINE_STEP
    toks += _buttons(["Next"], ROW_HINT)
    return _page(node, toks, interactive=True)


def _render_quest_entry(node, ctx):
    digits = node["digits"]
    values = (ctx or {}).get("values")
    toks = _title(node)
    for i, label in enumerate(node["items"]):
        row = ROW_FIRST + i * LINE_STEP
        toks += _line(f"{i + 1}. {label}", row)
        val = values[i].encode("ascii", "replace") if values else None
        toks += content.number_token(digits, col=28 - digits, row=row,
                                     style=ROW_STYLE, fill=0, value=val)
    toks += _buttons(["OK", "Fix", "Quit"], ROW_HINT)
    return _page(node, toks, interactive=True)


def _render_choice_entry(node, ctx):
    lst = {"title": node["title"], "back": node.get("back", "parent"),
           "items": [{"label": f"{i + 1}. {a}", "goto": None}
                     for i, a in enumerate(node["answers"])]}
    return _render_list(lst, ctx)


def _render_confirm(node, ctx):
    answer = (ctx or {}).get("answer", "?")
    toks = _title(node)
    y = ROW_FIRST
    for part in node["text"].split("\n"):
        for ln in _wrap_lines(part.replace("{answer}", answer)):
            toks += _line(ln, y)
            y += LINE_STEP
    toks += _buttons(["OK", "Fix", "Quit"], ROW_HINT)
    return _page(node, toks, interactive=True)


def _render_search(node, ctx):
    toks = _title(node)
    toks += _line("Type a title. The . key", ROW_FIRST)
    toks += _line("opens the keyboard.", ROW_FIRST + LINE_STEP)
    toks += _line("Name:", 12, col=3)
    toks += content.input_token(node.get("width", 12), col=10, row=12,
                                style=ROW_STYLE, fill=0)
    toks += _buttons(["Search", "All"], ROW_HINT)
    return _page(node, toks, interactive=True)


_RENDER = {
    "list": _render_list,
    "record": _render_record,
    "detail": _render_detail,
    "prose": _render_prose,
    "search": _render_search,
}


def _node(nid):
    results = SESSION_STATE.get("results")
    if results and nid in results:
        return results[nid]
    return NODES[nid]


def _render(nid, ctx=None):
    node = _node(nid)
    kind = node["type"]
    if kind == "quest-num":
        fn = _render_quest_entry if nid.endswith("@entry") else _render_question
    elif kind == "quest-choice":
        if nid.endswith("@entry"):
            fn = _render_choice_entry
        elif nid.endswith("@confirm"):
            fn = _render_confirm
        else:
            fn = _render_question
    else:
        fn = _RENDER[kind]
    return fn(node, ctx)


# ------------------------------------------------------------------ routing

def _serve(nid, ctx=None):
    SESSION_STATE["node"] = nid
    return _render(nid, ctx)


def _push(nid):
    SESSION_STATE["stack"].append(SESSION_STATE["node"])
    return nid


def _pop(n=1):
    st = SESSION_STATE
    for _ in range(n):
        if st["stack"]:
            st["node"] = st["stack"].pop()
    return _serve(st["node"] or SITE["preview"])


def _goto_item(node, item):
    target = item["goto"]
    if not item.get("sibling"):
        _push(target)
    return _serve(target)


def _pick(pay):
    """Which row a list submit names, 0-based.

    A type-4 field emits TWO digits ($99AF -> $99F9 splits tens and units) for
    whichever row the cursor is on; a type-5 cycler emits one for its selection.
    Both sit at the end of the payload, behind $98BB's leading '0'.
    """
    if LIST_STYLE == "cursor":
        if len(pay) < 3:
            raise ValueError(f"a cursor list submit is 3+ bytes, got {pay!r}")
        return (pay[-2] & 0x0F) * 10 + (pay[-1] & 0x0F) - 1
    return (pay[-1] & 0x0F) - 1


def _submit(pay):
    nid = SESSION_STATE["node"]
    node = _node(nid)
    kind = node["type"]
    if kind == "list":
        idx = _pick(pay)
        if not 0 <= idx < len(node["items"]):
            raise ValueError(f"selection {pay!r} -> row {idx} out of range "
                             f"on {nid} ({len(node['items'])} items)")
        return _goto_item(node, node["items"][idx])
    if kind == "search":
        text = pay[1:-1].decode("ascii", "replace").strip()
        want = pay[-1] - 0x30
        matches = _query_items(dict(node.get("query", {})), back_catalog=True)
        if want == 1 and text:
            matches = [m for m in matches
                       if text.upper() in m.get("text", "").upper()]
        title = node.get("results_title", node["title"])
        lst = {"type": "list", "title": title, "back": "parent",
               "items": matches or [{"label": "Nothing found", "goto": nid,
                                     "sibling": True}]}
        SESSION_STATE["results"] = {"@results": lst}
        _push("@results")
        return _serve("@results")
    if kind == "quest-num":
        if not nid.endswith("@entry"):
            _push(nid + "@entry")
            return _serve(nid + "@entry")
        n, digits = len(node["items"]), node["digits"]
        vals = [pay[1 + i * digits:1 + (i + 1) * digits].decode("ascii", "replace")
                for i in range(n)]
        want = pay[-1] - 0x30
        if want == 1:
            SESSION_STATE["quest"][nid] = vals
            _push(node["thanks"])
            return _serve(node["thanks"])
        if want == 2:
            return _serve(nid, {"values": vals})
        return _pop()
    if kind == "quest-choice":
        if nid.endswith("@confirm"):
            want = pay[-1] - 0x30
            if want == 1:
                _push(node["thanks"])
                return _serve(node["thanks"])
            if want == 2:
                return _pop()
            return _pop(2)
        if nid.endswith("@entry"):
            # The choice page IS a list, so it submits the same way.
            idx = _pick(pay)
            if not 0 <= idx < len(node["answers"]):
                raise ValueError(f"answer {pay!r} -> {idx} out of range "
                                 f"on {nid}")
            base = nid[:-len("@entry")]
            SESSION_STATE["quest"][base] = node["answers"][idx]
            _push(base + "@confirm")
            return _serve(base + "@confirm",
                          {"answer": node["answers"][idx]})
        _push(nid + "@entry")
        return _serve(nid + "@entry")
    raise ValueError(f"a {kind} page ({nid}) takes no submit")


def page(req):
    """The router.  req is frame.split_request()'s dict, or None at load."""
    if req is None:
        return _render(SITE["preview"])
    pay = req["payload"]
    sec = req["section"].decode("ascii", "replace")
    if pay == b"M":
        return _pop()
    if len(pay) == 1 and sec in MENU_CODES:
        SESSION_STATE["stack"] = []
        SESSION_STATE["results"] = None
        return _serve(MENU_CODES[sec])
    if SESSION_STATE["node"] is None:
        # A deep request with no state: a reload lost it, or the walk began
        # mid-session.  Serve the section's own page rather than guessing.
        if sec in MENU_CODES:
            return _serve(MENU_CODES[sec])
        return _render(SITE["preview"])
    return _submit(pay)


# ---------------------------------------------------------------- validation

def _confirm_ctx(nid):
    if nid.endswith("@confirm"):
        return {"answer": "PLACEHOLDER"}
    return None


def _results_list(nid, node):
    """What a search page serves once it has run its query."""
    items = _query_items(dict(node.get("query", {})), back_catalog=True)
    return {"type": "list", "title": node["title"], "back": "parent",
            "items": items or [{"label": "Nothing found", "goto": nid}]}


def _check_blocks():
    for nid in sorted(NODES):
        yield nid, lambda nid=nid: _render(nid, _confirm_ctx(nid))
    for nid in sorted(NODES):
        node = NODES[nid]
        if node["type"] == "search":
            lst = _results_list(nid, node)
            yield f"{nid}[results]", lambda n=lst: _render_list(n, None)


def _all_lists():
    """Every list a cursor walk has to reach every row of."""
    for nid in sorted(NODES):
        node = NODES[nid]
        if node["type"] == "list":
            yield nid, node
        elif node["type"] == "search":
            yield f"{nid}[results]", _results_list(nid, node)


def _check_one(card, blk):
    chk = card.check_content(blk)
    if chk["error"]:
        return f"bank 5 rejects it: {chk['error']}"
    m = card.measure(blk)
    if m["error"]:
        return f"the measure pass rejects it: {m['error']}"
    if m["modeled"] and m["interactive"]:
        return "measures interactive=True (a nested sub-field -- the serve14 hang)"
    try:
        blocks = frame.build_page_blocks(blk)
    except ValueError as exc:
        # Over $EF53's ceiling: a problem to report per page, not a traceback
        # that stops the sweep before the other nodes are checked.
        return str(exc)
    v = frame.card_receive(blocks)
    if v["error"]:
        return f"the receive path rejects it: {v['error']} at {v['where']}"
    if not v["complete"]:
        return "the message never closes"
    if blk[1] == B1_FORM and m["modeled"]:
        # A menu selection is one byte, so every form submit must be longer or
        # the router cannot tell them apart.  Types 4/8 emit two digits and
        # type 5 one, all behind $98BB's leading '0'; a type-6 cycler would
        # overwrite that '0' in place and submit a single byte, so it is out.
        kinds = {f.get("type") for f in m["fields"] if f["kind"] == "field"}
        if not kinds & {4, 5, 8}:
            return ("interactive page with no row field (types 4/5/8): a "
                    f"submit could be 1 byte and collide with a menu code "
                    f"(got types {sorted(k for k in kinds if k)})")
    return None


def check_all():
    """Every node through the card's own validators.  -> list of problems."""
    probs, card = [], content.checker()
    for code, target in sorted(MENU_CODES.items()):
        if target not in NODES:
            probs.append(f"menu {code}: goto {target!r} is not a node")
    for nid, node in sorted(NODES.items()):
        if node["type"] != "list":
            continue
        for it in node.get("items", []):
            tgt = it.get("goto")
            if tgt and tgt not in NODES and not tgt.startswith("@"):
                probs.append(f"{nid}: goto {tgt!r} is not a node")
    for nid, build in _check_blocks():
        try:
            why = _check_one(card, build())
        except Exception as exc:                                 # noqa: BLE001
            probs.append(f"{nid}: {type(exc).__name__}: {exc}")
            continue
        if why:
            probs.append(f"{nid}: {why}")
    return probs


MENU_CONTENT = None
if SITE.get("options", {}).get("today_first"):
    _today = dict(NODES[SITE["options"]["today_node"]], back="menu")
    MENU_CONTENT = _render_prose(_today, None)


# ------------------------------------------------------------------ __main__

def _req(section, payload):
    return {"section": section.encode("ascii"), "command": b"13",
            "spare": b"0000", "payload": payload}


def _rowpay(n):
    """What the card sends when row n (1-based) of a list is chosen."""
    return b"0" + (b"%02d" % n if LIST_STYLE == "cursor" else b"%d" % n)


def _walk():
    """Drive the router over the whole tree with synthetic requests."""
    steps, bad = 0, 0

    def go(what, req):
        nonlocal steps, bad
        steps += 1
        try:
            blk = page(req)
            why = _check_one(content.checker(), blk)
        except Exception as exc:                                 # noqa: BLE001
            blk, why = None, f"{type(exc).__name__}: {exc}"
        if why:
            bad += 1
            print(f"  FAIL {what}: {why}")
        return blk

    for code in sorted(MENU_CODES):
        go(f"menu {code}", _req(code, b"0"))
        seen, guard = set(), 0
        while guard < 40:
            guard += 1
            nid = SESSION_STATE["node"]
            node = _node(nid)
            kind = node["type"]
            if (nid, kind) in seen:
                break
            seen.add((nid, kind))
            if kind == "list":
                go(f"{nid} pick 1", _req(code, _rowpay(1)))
            elif kind == "search":
                go(f"{nid} search all", _req(code, b"0" + b" " * 4 + b"2"))
            elif kind == "quest-num":
                if nid.endswith("@entry"):
                    n, d = len(node["items"]), node["digits"]
                    go(f"{nid} ok", _req(code, b"0" + b"7" * (n * d) + b"1"))
                else:
                    go(f"{nid} next", _req(code, b"01"))
            elif kind == "quest-choice":
                if nid.endswith("@confirm"):
                    go(f"{nid} ok", _req(code, b"01"))
                elif nid.endswith("@entry"):
                    go(f"{nid} answer 1", _req(code, _rowpay(1)))
                else:
                    go(f"{nid} next", _req(code, b"01"))
            else:
                go(f"{nid} pop", _req(code, b"M"))
                if SESSION_STATE["node"] == nid:
                    break
    print(f"walk: {steps} step(s), {bad} failure(s)")
    return bad == 0


def _deep(card):
    """Walk every list's cursor: each row must submit its own 1-based index."""
    bad = 0
    if not card.modeled:
        print("\ncursor walk: skipped -- it runs the card's own passes, so it "
              "needs a ROM image (set $SMC_ROM)")
        return 0
    print("\ncursor walk -- $96B6 -> $9BC7 -> $98A8, every row of every list:")
    for nid, node in _all_lists():
        r = card.reachable(_render_list(node, None))
        want = sorted(_rowpay(i + 1) for i in range(len(node["items"])))
        if r["error"]:
            why = f"the walk faulted: {r['error']}"
        elif sorted(r["payloads"]) != want:
            got = b" ".join(r["payloads"]).decode("ascii", "replace")
            why = f"{len(r['payloads'])} of {len(node['items'])} rows: {got}"
        else:
            why = None
        if why:
            bad += 1
        print(f"{nid:<28} {len(node['items']):>3} rows  {r['panes']} pane(s)"
              f"  {why or 'ok'}")
    return bad


if __name__ == "__main__":
    card = content.checker()
    bad = 0
    # A message is 2048 B at $6100 and the 10-byte code+sub+spare prefix is
    # spent once, so this is what a page has to fit in ($EF53 -> 4703).
    room = frame.WRAM_IN_MAX - 10
    for nid, build in _check_blocks():
        try:
            blk = build()
            why = _check_one(card, blk)
        except Exception as exc:                                 # noqa: BLE001
            bad += 1
            print(f"{nid:<28} BUILD FAILED: {exc}")
            continue
        m = card.measure(blk)
        n = len(frame.build_page_blocks(blk)) if len(blk) <= room else 0
        size = f"{len(blk)}B" + (f"/{n}blk" if n > 1 else "")
        if m["modeled"]:
            fields = ",".join("t%d" % f["type"] if f["kind"] == "field"
                              else f["kind"] for f in m["fields"]) or "-"
            panes = f"panes={m['c3'] & 0x7F}"
        else:
            fields, panes = "(needs a ROM)", "panes=?"
        if why:
            bad += 1
        print(f"{nid:<28} {size:>9} free={room - len(blk):>5}"
              f"  {panes}  fields={fields:<12} {why or 'ok'}")
    if "--deep" in sys.argv:
        bad += _deep(card)
    probs = check_all()
    for p in probs:
        print("!!", p)
    SESSION_STATE.update({"node": None, "stack": [], "results": None})
    ok = _walk() and not probs and not bad
    print("site     :", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
