## What is ModernSMC?
ModernSMC is my attempt at properly reviving Super Mario Club's servers,
using ThroatyMumbo's SMC-Server repository as a base.
When everything is ready to go, i'll update this.


## Original README


# Super Mario Club mock server

**Super Mario Club** was a subscription service for the **Famicom Network
System**, Nintendo's 1988 modem adapter for the Famicom. Retailers and software
publishers dialed in over an ordinary phone line to read release calendars,
sales charts and review scores. The service shut down decades ago, so the
cartridge, which is basically just a web browser, has had nothing to talk to since.

This repo contains the missing server side, which serves mock data that aims to
replicate the look and feel of the original service. This is primarily for
educational purposes. None of the server content is meant to be an accurate
historical record. Most of it is LLM-generated and based on plausible approximation.

Everything here was derived by reverse-engineering the cartridge's own 6502
code. **No Nintendo code or data is distributed with it.**

## Setup

You need a Famicom + the network system adapter, a copy of Super Mario Club,
a phone-line sim, and a USB modem that will answer at 1200 bps.

You'll probably also need a relay board that can reverse the phone line polarity.
The card waits for the polarity reversal that NTT's exchange used as answer supervision,
and no line simulator produces it (that I own, anyway).

```
python3 server.py --call
```

Live demo using a DLE-300 phone sim + relay module hooked up to a Pico Plus 2 W: https://youtu.be/xiyCKUl93Uo?t=2257

## Editing

The page file is re-read from disk before every reply, so it can be edited
**during a live call**: save, press B (目次) on the Famicom, and the card draws
the new page. A page the card would reject is refused as it loads and the last
good one keeps serving, so a typo costs a log line rather than a re-dial.

- **`site_page.py` + `site/`** - the default. A whole service as a JSON tree:
  menu, release calendars, game records, title search, questionnaires. Edit the
  JSON, not the Python.
- **`page.py`** - `--probe-page`. One page at a time behind an `EXPERIMENT =`
  string, for pinning down a single widget on the bench.

Run `python3 server.py --check` in a second terminal to see the verdict on
what you just saved, without a card.

## Layout

| | |
|---|---|
| `server.py` | the far end: framing, routing, the modem session |
| `frame.py` | the frame codec both directions, and the card's four inbound checks |
| `content.py` | records, content streams, tokens, widgets - the builders |
| `cardmodel.py` | the card's acceptance rules in Python; no ROM needed |
| `message.py` | the `$B60D` word-wrap engine |
| `site_page.py`, `site/` | the served service, as data |
| `page.py` | the bench experiment dial |
| `tools/` | serial-port discovery, the relay driver, a 6502 emulator |
| `testdata/` | two recorded far-end captures the self-tests replay |

## Legal

The Famicom Network System, Super Mario Club, Famicom, Game Boy and Nintendo
are trademarks of Nintendo. This project is not affiliated with, endorsed by or
connected to Nintendo in any way; those names appear only to say what this
software interoperates with.

No cartridge code, ROM image, artwork or manual text is distributed here. The
implementation is an independent one, written from behavioral analysis of the
protocol for the purpose of interoperating with hardware people already own.

**Everything under `site/` is invented.** The release dates, sales forecasts,
review scores, retailer charts and publisher announcements are period-plausible
fiction written to exercise the protocol - they are not Nintendo's data, not a
reconstruction of what the original service transmitted, and should not be
cited as historical record.

MIT licensed; see `LICENSE`.
