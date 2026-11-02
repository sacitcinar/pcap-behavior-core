"""Conservative FTP control-channel observations from a completed classic-PCAP index.

Read only observed, contiguous TCP bytes with verified overlap; no credentials,
arguments, paths or raw payloads are retained. This module does not issue findings,
interpret maliciousness, or claim that STOR/RETR completed a file transfer.

Scope: TCP port 21 plaintext control channel, first 2,000 eligible flows. Gaps,
truncation, fragmentation and ambiguous retransmissions limit observations. This
is deliberately not a general TCP stream reconstruction facility.
"""
from __future__ import annotations

from collections import Counter
from contextlib import closing
from pathlib import Path
import json
import re
import sqlite3
import struct

from .decoders import decode
from .reader import PcapReader, Record

# Do not store FTP command arguments (USER, PASS, STOR paths, and so on).
_COMMANDS = frozenset('USER PASS ACCT CWD CDUP SMNT REIN QUIT PORT PASV TYPE STRU MODE RETR STOR STOU APPE ALLO REST RNFR RNTO ABOR DELE RMD MKD PWD LIST NLST SITE SYST STAT HELP NOOP FEAT OPTS AUTH ADAT PBSZ PROT CCC EPSV EPRT SIZE MDTM MLSD MLST LANG HOST CLNT'.split())
_CMD_RE = re.compile(rb'^([A-Za-z]{3,5})(?:[ \t][\x20-\x7e]*)?$')
_REPLY_RE = re.compile(rb'^([1-5][0-9]{2})[ -][\x20-\x7e]*$')
_MAX_BYTES = 65536
_MAX_LINE = 1024
_MAX_LINES = 300
_MAX_FLOWS = 2000


class _ContiguousLines:
    """Per-direction, bounded, in-file-order TCP byte reader.

    The bounded tail verifies retransmissions before accepting new bytes.
    Sequence gaps cause a stop, rather than fabricated gap-filling text.
    """
    def __init__(self):
        self.expected: int | None = None
        self.tail = b''
        self.pending = b''
        self.pending_frames: list[int] = []
        self.lines: list[tuple[bytes, tuple[int, ...]]] = []
        self.bytes_accepted = 0
        self.limit_reason: str | None = None

    def feed(self, seq: int, data: bytes, frame_no: int):
        if not data or self.limit_reason is not None:
            return
        if self.expected is None:
            self.expected = seq
        delta = ((seq - self.expected + 0x80000000) & 0xffffffff) - 0x80000000
        if delta > 0:
            self.limit_reason = 'tcp_sequence_gap'
            return
        if delta < 0:
            overlap = -delta
            # Compare precisely the retransmitted byte range, including when
            # the entire packet is an older subset of the accepted sequence.
            portion = min(overlap, len(data))
            if (overlap > len(self.tail) or
                    data[:portion] != self.tail[-overlap:][:portion]):
                self.limit_reason = 'unverifiable_or_conflicting_retransmission'
                # Any previous parsed lines from an ambiguous direction cannot
                # be treated as fully trustworthy.
                self.lines.clear()
                return
            if overlap >= len(data):
                return
            data = data[overlap:]
        if self.bytes_accepted + len(data) > _MAX_BYTES:
            self.limit_reason = 'byte_limit_reached'
            return
        self.expected = (self.expected + len(data)) & 0xffffffff
        self.bytes_accepted += len(data)
        self.tail = (self.tail + data)[-_MAX_BYTES:]
        # A single packet can contain several commands. Preserve packet refs
        # for each observed complete line, without retaining command arguments.
        for b in data:
            self.pending += bytes((b,))
            if frame_no not in self.pending_frames and len(self.pending_frames) < 16:
                self.pending_frames.append(frame_no)
            if len(self.pending) > _MAX_LINE:
                self.limit_reason = 'line_limit_exceeded'
                self.pending = b''
                return
            if self.pending.endswith(b'\r\n'):
                line = self.pending[:-2]
                self.lines.append((line, tuple(self.pending_frames)))
                self.pending = b''
                self.pending_frames.clear()
                if len(self.lines) >= _MAX_LINES:
                    self.limit_reason = 'line_count_limit_reached'
                    return


def _parse_line(line: bytes, *, from_server: bool) -> tuple[str, str] | None:
    if from_server:
        match = _REPLY_RE.fullmatch(line)
        return ('reply', match.group(1).decode('ascii')) if match else None
    match = _CMD_RE.fullmatch(line)
    if not match:
        return None
    verb = match.group(1).decode('ascii').upper()
    return ('command', verb) if verb in _COMMANDS else None


def collect_ftp_control(pcap_path: str | Path, index_path: str | Path, *,
                        max_preview_sessions: int = 100) -> dict:
    """Observe plaintext FTP control *syntax*, without modifying the index.

    Payload is fetched by indexed PCAP record offset; no full-PCAP second scan.
    Returned summaries are safe to serialize: no raw FTP arguments or payload.
    """
    if type(max_preview_sessions) is not int or max_preview_sessions < 0:
        raise ValueError('max_preview_sessions must be nonnegative')
    sessions: dict[str, dict] = {}
    overflow_flows: set[str] = set()
    with closing(sqlite3.connect(f'{Path(index_path).resolve().as_uri()}?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute('''
            SELECT p.frame_no, p.record_offset, p.captured_len, p.src_ip, p.dst_ip,
                   p.src_port, p.dst_port, p.tcp_seq, p.parse_status,
                   p.fragment_state, fp.flow_id
            FROM packets p JOIN flow_packets fp ON fp.frame_no=p.frame_no
            WHERE p.protocol=6 AND (p.src_port=21 OR p.dst_port=21)
              AND p.l4_captured_payload_bytes>0
            ORDER BY p.frame_no''')
        with PcapReader(pcap_path) as reader, Path(pcap_path).open('rb') as raw_file:
            record_header = struct.Struct(reader.header.endian + 'IIII')
            for row in rows:
                fid = row['flow_id']
                if fid in overflow_flows:
                    continue
                if fid not in sessions:
                    if len(sessions) >= _MAX_FLOWS:
                        overflow_flows.add(fid)
                        continue
                    server_ip = row['src_ip'] if row['src_port'] == 21 else row['dst_ip']
                    client_ip = row['dst_ip'] if row['src_port'] == 21 else row['src_ip']
                    sessions[fid] = dict(flow_id=fid, client_ip=client_ip, server_ip=server_ip,
                                         server_port=21, streams={'client': _ContiguousLines(),
                                                                  'server': _ContiguousLines()},
                                         incomplete_packet_count=0)
                session = sessions.get(fid)
                if session is None:
                    continue
                if row['parse_status'] != 'ok' or row['fragment_state'] not in ('unfragmented', 'atomic'):
                    session['incomplete_packet_count'] += 1
                    continue
                # Ensure the bytes reloaded from the original PCAP correspond
                # exactly to the indexed record; fail closed on mismatch.
                raw_file.seek(row['record_offset'])
                h = raw_file.read(16)
                if len(h) != 16:
                    raise ValueError('Indexed PCAP record header not readable')
                sec, frac, caplen, wirelen = record_header.unpack(h)
                if caplen != row['captured_len']:
                    raise ValueError('PCAP record and index disagree on captured length')
                wire = raw_file.read(caplen)
                if len(wire) != caplen:
                    raise ValueError('Indexed PCAP record truncated during FTP inspection')
                pkt = decode(Record(row['frame_no'], row['record_offset'], 0, caplen, wirelen, wire),
                             reader.header.linktype)
                if (pkt.src_ip != row['src_ip'] or pkt.dst_ip != row['dst_ip'] or
                        pkt.src_port != row['src_port'] or pkt.dst_port != row['dst_port'] or
                        pkt.tcp_seq != row['tcp_seq']):
                    raise ValueError('PCAP record and index disagree on FTP packet identity')
                if pkt.parse_status != 'ok' or pkt.fragment_state not in ('unfragmented','atomic'):
                    session['incomplete_packet_count'] += 1
                    continue
                side = 'server' if pkt.src_port == 21 else 'client'
                session['streams'][side].feed(pkt.tcp_seq, pkt.payload, row['frame_no'])

    summaries = []
    counts = Counter()
    for session in sessions.values():
        commands, replies = Counter(), Counter()
        frames = set()
        for side, stream in session['streams'].items():
            for line, refs in stream.lines:
                parsed = _parse_line(line, from_server=(side == 'server'))
                if parsed is None:
                    continue
                kind, label = parsed
                (replies if kind == 'reply' else commands)[label] += 1
                frames.update(refs)
        if not commands and not replies:
            continue
        counts['sessions'] += 1
        counts['commands'] += sum(commands.values())
        counts['replies'] += sum(replies.values())
        limited = [x.limit_reason for x in session['streams'].values() if x.limit_reason]
        if session['incomplete_packet_count']:
            limited.append('partial_or_fragmented_packets_skipped')
        summaries.append(dict(flow_id=session['flow_id'], client_ip=session['client_ip'],
                              server_ip=session['server_ip'], server_port=21,
                              observed_commands=dict(sorted(commands.items())),
                              observed_reply_codes=dict(sorted(replies.items())),
                              packet_refs=sorted(frames)[:32],
                              observation_limited=bool(limited),
                              limitations=sorted(set(limited))))
    summaries.sort(key=lambda s:(s['client_ip'],s['server_ip'],s['flow_id']))
    return dict(protocol='FTP_control_plaintext', scope='TCP port 21; visible complete control lines only',
                sessions_observed=counts['sessions'],
                commands_observed=counts['commands'], replies_observed=counts['replies'],
                sessions=summaries[:max_preview_sessions],
                sessions_truncated=len(summaries)>max_preview_sessions,
                eligible_flows_skipped=len(overflow_flows),
                no_security_findings_created=True,
                excludes_credentials_and_command_arguments=True)
