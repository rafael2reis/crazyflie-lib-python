"""Crazyflie BLE framing and the mandatory bench-only packet policy.

Copyright (C) 2026. Licensed under GPL-3.0-or-later, as part of cflib.
"""


class FrameError(ValueError):
    pass


class DownDecoder:
    def __init__(self):
        self.reset()

    def reset(self):
        self.pid = None
        self.expected = 0
        self.data = bytearray()

    def feed(self, value):
        try:
            if not 2 <= len(value) <= 20:
                raise FrameError('Invalid BLE notification size')
            control = value[0]
            pid = (control >> 5) & 3
            if control & 0x80:
                if self.pid is not None:
                    raise FrameError('New start before previous packet completed')
                self.pid, self.expected = pid, (control & 31) + 1
            elif self.pid is None or pid != self.pid or control & 31:
                raise FrameError('Missing start, wrong PID, or invalid continuation')
            self.data.extend(value[1:])
            if len(self.data) > self.expected:
                raise FrameError('Notification exceeds declared packet length')
            if len(self.data) == self.expected:
                packet = bytes(self.data)
                self.reset()
                return packet
            return None
        except FrameError:
            self.reset()
            raise


def fragment_up(packet, pid):
    if not 1 <= len(packet) <= 31:
        raise FrameError('CRTP packet must contain 1..31 bytes')
    first = bytes([0x80 | ((pid & 3) << 5) | (len(packet) - 1)]) + packet[:19]
    return [first] + ([bytes([(pid & 3) << 5]) + packet[19:]] if len(packet) > 19 else [])


def bench_allowed(packet):
    """Allow read/query/log operations; flight and persistent writes stay blocked."""
    if not 1 <= len(packet) <= 31:
        return False
    h, data = packet[0] & 0xF3, packet[1:]
    if packet == b'\xff':
        return True
    if h == 0xF0:  # Echo, no bootloader/null payloads
        return True
    if h == 0xF1:  # Firmware identification, not link-layer control
        return data == b'\x00'
    if h == 0xD1:
        return data in (b'\x00', b'\x01', b'\x02')
    if h in (0x20, 0x50):  # Param/log TOC v1/v2
        return (data in (b'\x01', b'\x03') or
                len(data) == 2 and data[0] == 0 or
                len(data) == 3 and data[0] == 2)
    if h == 0x21:
        return len(data) in (1, 2)  # Param value read
    if h == 0x23:
        return len(data) == 3 and data[0] in (2, 4, 6, 7, 8)
    if h == 0x40:  # Memory enumeration only
        return data in (b'\x00', b'\x01') or len(data) == 2 and data[0] == 2
    if h == 0x51 and data:
        if data[0] in (2, 4):  # Delete/stop an explicitly selected log block
            return len(data) == 2
        if data[0] == 3:
            return len(data) == 3 and data[2] >= 10  # >=100 ms
        if data[0] == 8:
            return len(data) == 4 and int.from_bytes(data[2:], 'little') >= 100
        if data[0] in (6, 7):  # TOC-backed logging only, never raw-memory ops
            return (len(data) >= 5 and (len(data) - 2) % 3 == 0 and
                    all(1 <= data[i] & 15 <= 8 and 1 <= data[i] >> 4 <= 8 and
                        data[i+1:i+3] != b'\xff\xff' for i in range(2, len(data), 3)))
    return False
