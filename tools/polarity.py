#!/usr/bin/env python3
"""The line-polarity relay driver, over the relay CDC port of the debug probe."""
import time


def _log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class Polarity:
    """The DPDT cross-over in the two-wire line.

    Two channels of a 5 V relay module wired as a cross-over (ch1 COM -> card
    tip, NC/NO = line tip/ring; ch2 COM -> card ring, NC/NO = line ring/tip)
    swap the battery the card sees.  That is the answer supervision `g`
    ($EBAB) waits for: it wants ($4126|$3F)^$C0 == $49, the complement of
    whatever polarity $E8FC latched at off-hook.  Neither line simulator can
    reverse battery, so the relays stand in for the exchange.

    One character per command, answered with a status line:
        1 reverse   0 normal   p push-pull   o open-drain   ? status
    The reply is what makes this trustworthy: a relay that never moved is the
    one failure mode that looks exactly like `g` not caring.
    """

    DRIVE = {"push-pull": "p", "open-drain": "o"}

    def __init__(self, port, drive=None, log=None):
        self.ser, self.state, self.last = None, False, ""
        self.log = log or _log
        if not port:
            return
        import serial
        self.ser = serial.Serial(port, 115200, timeout=0.5)
        if drive:
            self._cmd(self.DRIVE[drive])
        self.set(False)

    @property
    def live(self):
        return self.ser is not None

    def _cmd(self, ch):
        self.ser.reset_input_buffer()
        self.ser.write(ch.encode())
        self.ser.flush()
        self.last = self.ser.readline().decode("ascii", "replace").strip()
        return self.last

    def set(self, reverse):
        """Command the relays.  A no-op when no port was given, so the
        manual-switch workflow still works unchanged."""
        self.state = bool(reverse)
        if self.ser is None:
            return ""
        reply = self._cmd("1" if self.state else "0")
        want = "reversed" if self.state else "normal"
        if ("polarity=" + want) not in reply:
            self.log("!! relay did not confirm polarity=%s -- got %r"
                     % (want, reply))
        return reply

    def close(self):
        """Send `0` and release the port.  Idempotent; register with atexit.

        A run that ends reversed leaves the line looking permanently answered
        and the next call starts from the wrong state.
        """
        if self.ser is None:
            return
        try:
            self.set(False)
            self.log("polarity: relays restored to normal")
        except Exception as exc:                      # a dead port must not
            self.log(f"!! polarity: could not restore normal on exit: {exc}")
        finally:
            ser, self.ser = self.ser, None            # mask the real summary
            try:
                ser.close()
            except Exception:
                pass
