"""Classic PCAP record reader. The file is never modified."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Iterator

MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 'microsecond'),
    b'\xa1\xb2\xc3\xd4': ('>', 'microsecond'),
    b'\x4d\x3c\xb2\xa1': ('<', 'nanosecond'),
    b'\xa1\xb2\x3c\x4d': ('>', 'nanosecond'),
}

class PcapFormatError(ValueError):
    pass

@dataclass(frozen=True, slots=True)
class PcapHeader:
    endian: str
    byte_order: str
    precision: str
    version_major: int
    version_minor: int
    snaplen: int
    linktype: int

@dataclass(frozen=True, slots=True)
class Record:
    frame_no: int
    offset: int
    ts_ns: int
    captured_len: int
    wire_len: int
    raw: bytes

class PcapReader:
    def __init__(self, path: str | Path, max_record_bytes: int = 32 * 1024 * 1024):
        self.path = Path(path)
        self.max_record_bytes = max_record_bytes
        self.header: PcapHeader | None = None
        self.warnings: list[dict] = []
        self._file = None

    def __enter__(self) -> 'PcapReader':
        self._file = self.path.open('rb')
        try:
            raw = self._file.read(24)
            if len(raw) != 24:
                raise PcapFormatError('PCAP global header must be 24 bytes')
            if raw[:4] == b'\x0a\x0d\x0d\x0a':
                raise PcapFormatError('pcapng input is not accepted; use a classic PCAP file')
            if raw[:4] not in MAGICS:
                raise PcapFormatError('Unrecognized classic PCAP magic')
            endian, precision = MAGICS[raw[:4]]
            major, minor, _thiszone, _sigfigs, snaplen, network = struct.unpack(endian + 'HHiIII', raw[4:])
            if major != 2 or minor not in (4,):
                raise PcapFormatError(f'Unsupported PCAP format version: {major}.{minor}')
            if snaplen <= 0:
                raise PcapFormatError('Invalid PCAP snaplen')
            self.header = PcapHeader(endian, 'little' if endian == '<' else 'big', precision, major, minor, snaplen, network & 0xffff)
        except Exception:
            self._file.close()
            self._file = None
            raise
        return self

    def __exit__(self, *_):
        if self._file:
            self._file.close()
            self._file = None

    def __iter__(self) -> Iterator[Record]:
        if self._file is None or self.header is None:
            raise RuntimeError('Use PcapReader as a context manager')
        frame = 0
        hdr_struct = struct.Struct(self.header.endian + 'IIII')
        precision_unit = 1_000_000_000 if self.header.precision == 'nanosecond' else 1_000_000
        scale = 1 if self.header.precision == 'nanosecond' else 1000
        while True:
            offset = self._file.tell()
            record_hdr = self._file.read(16)
            if not record_hdr:
                break
            if len(record_hdr) != 16:
                self.warnings.append({'code': 'truncated_record_header', 'offset': offset, 'bytes_present': len(record_hdr)})
                break
            sec, sub, caplen, wirelen = hdr_struct.unpack(record_hdr)
            if caplen > self.max_record_bytes:
                self.warnings.append({'code': 'oversized_record', 'offset': offset, 'captured_len': caplen})
                break
            payload = self._file.read(caplen)
            if len(payload) != caplen:
                self.warnings.append({'code': 'truncated_record_payload', 'offset': offset, 'expected': caplen, 'actual': len(payload)})
                break
            frame += 1
            if sub >= precision_unit:
                self.warnings.append({'code': 'invalid_fractional_timestamp', 'frame': frame, 'subseconds': sub})
            if caplen > wirelen:
                self.warnings.append({'code': 'captured_len_exceeds_wire_len', 'frame': frame})
            if caplen > self.header.snaplen:
                self.warnings.append({'code': 'captured_len_exceeds_snaplen', 'frame': frame})
            yield Record(frame, offset, sec * 1_000_000_000 + sub * scale, caplen, wirelen, payload)
