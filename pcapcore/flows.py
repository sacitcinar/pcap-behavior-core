"""Bidirectional conversations, TCP attempts, UDP pseudo-flows.

Connection state reflects observed packets rather than inferred states.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
from .decoders import Decoded

SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04

def _id(prefix: str, *parts) -> str:
    payload = json.dumps(parts, ensure_ascii=True, separators=(',', ':')).encode()
    return prefix + hashlib.sha256(payload).hexdigest()[:20]


def _endpoint(ip: str, port: int) -> tuple[str, int]:
    return ip, port


def _endpoint_order(item: tuple[str, int]) -> tuple[int, int, int]:
    a = ipaddress.ip_address(item[0])
    return a.version, int(a), item[1]


def conversation_key(p: Decoded) -> tuple:
    a, b = _endpoint(p.src_ip, p.src_port), _endpoint(p.dst_ip, p.dst_port)
    x, y = sorted((a, b), key=_endpoint_order)
    return ('tcp' if p.ip_protocol == 6 else 'udp', x, y)


class UniqueByteIntervals:
    """Merge observed TCP sequence ranges, retransmits counted once.

    Estimates captured, not delivered/ACKed application bytes. 32-bit wrap is
    handled relative to the first observed payload segment (half-range limit).
    """
    __slots__ = ('base', 'intervals')

    def __init__(self):
        self.base: int | None = None
        self.intervals: list[tuple[int, int]] = []

    def add(self, seq: int, size: int) -> None:
        if size <= 0:
            return
        if self.base is None:
            self.base = seq
        delta = (seq - self.base) & 0xffffffff
        if delta >= 0x80000000:
            delta -= 0x100000000
        low, high = delta, delta + size
        if not self.intervals:
            self.intervals.append((low, high)); return
        # Most traffic is ordered: merge directly with the tail.
        if low >= self.intervals[-1][0]:
            a, b = self.intervals[-1]
            if low <= b:
                self.intervals[-1] = (a, max(b, high))
            else:
                self.intervals.append((low, high))
            return
        import bisect
        i = bisect.bisect_left(self.intervals, (low, -1))
        if i > 0 and self.intervals[i - 1][1] >= low:
            i -= 1
        j = i
        while j < len(self.intervals) and self.intervals[j][0] <= high:
            low = min(low, self.intervals[j][0])
            high = max(high, self.intervals[j][1])
            j += 1
        self.intervals[i:j] = [(low, high)]

    @property
    def size(self) -> int:
        return sum(b - a for a, b in self.intervals)


@dataclass(slots=True)
class Flow:
    flow_id: str
    conversation_id: str
    attempt_ordinal: int
    protocol: str
    origin_ip: str
    origin_port: int
    responder_ip: str
    responder_port: int
    origin_basis: str
    first_seen_ns: int
    last_seen_ns: int
    orig_packet_count: int = 0
    resp_packet_count: int = 0
    orig_ip_declared_bytes: int = 0
    resp_ip_declared_bytes: int = 0
    orig_ip_captured_bytes: int = 0
    resp_ip_captured_bytes: int = 0
    orig_l4_payload_observed_bytes: int = 0
    resp_l4_payload_observed_bytes: int = 0
    packet_ref_count: int = 0
    packet_refs_sample: list[int] = field(default_factory=list)
    flow_visibility_flags: set[str] = field(default_factory=set)
    tcp_state_flags: set[str] = field(default_factory=set)
    _orig_unique: UniqueByteIntervals = field(default_factory=UniqueByteIntervals)
    _resp_unique: UniqueByteIntervals = field(default_factory=UniqueByteIntervals)
    _syn_seq: int | None = None
    _synack_seq: int | None = None
    _synack_valid: bool = False
    _handshake: bool = False
    _refused: bool = False
    _rst: bool = False
    _fin_orig: bool = False
    _fin_resp: bool = False
    _last_file_ts: int = 0

    def direction(self, p: Decoded) -> str:
        if p.src_ip == self.origin_ip and p.src_port == self.origin_port:
            return 'orig'
        return 'resp'

    def add(self, p: Decoded):
        d = self.direction(p)
        self.first_seen_ns = min(self.first_seen_ns, p.ts_ns)
        self.last_seen_ns = max(self.last_seen_ns, p.ts_ns)
        if p.ts_ns < self._last_file_ts:
            self.flow_visibility_flags.add('time_anomaly')
        self._last_file_ts = p.ts_ns
        setattr(self, d + '_packet_count', getattr(self, d + '_packet_count') + 1)
        setattr(self, d + '_ip_declared_bytes', getattr(self, d + '_ip_declared_bytes') + (p.ip_declared_bytes or 0))
        setattr(self, d + '_ip_captured_bytes', getattr(self, d + '_ip_captured_bytes') + (p.ip_captured_bytes or 0))
        setattr(self, d + '_l4_payload_observed_bytes', getattr(self, d + '_l4_payload_observed_bytes') + (p.l4_captured_payload_bytes or 0))
        if p.parse_status != 'ok' or 'ip_snaplen_or_truncation' in p.issues:
            self.flow_visibility_flags.add('truncated_or_partial')
        if p.fragment_state not in ('unfragmented', 'atomic'):
            self.flow_visibility_flags.add('fragmented')
        self.packet_ref_count += 1
        if len(self.packet_refs_sample) < 12:
            self.packet_refs_sample.append(p.frame_no)
        if self.protocol != 'tcp':
            return
        f = p.tcp_flags
        if f & SYN and f & ACK:
            self.tcp_state_flags.add('SYNACK')
            if d == 'resp' and self._syn_seq is not None and p.tcp_ack == ((self._syn_seq + 1) & 0xffffffff):
                self._synack_seq = p.tcp_seq
                self._synack_valid = True
        elif f & SYN:
            self.tcp_state_flags.add('SYN')
            if d == 'orig' and self._syn_seq is None:
                self._syn_seq = p.tcp_seq
        if f & ACK:
            self.tcp_state_flags.add('ACK')
            if d == 'orig' and not (f & SYN) and self._synack_valid and p.tcp_ack == ((self._synack_seq + 1) & 0xffffffff):
                self._handshake = True
        if f & RST:
            self.tcp_state_flags.add('RST'); self._rst = True
            if (d == 'resp' and self._syn_seq is not None and not self._synack_valid
                    and p.tcp_ack == ((self._syn_seq + 1) & 0xffffffff) and f & ACK):
                self._refused = True
        if f & FIN:
            self.tcp_state_flags.add('FIN')
            if d == 'orig': self._fin_orig = True
            else: self._fin_resp = True
        if (p.l4_captured_payload_bytes or 0) > 0:
            self.tcp_state_flags.add('DATA')
            if p.tcp_seq is not None:
                (self._orig_unique if d == 'orig' else self._resp_unique).add(p.tcp_seq, p.l4_captured_payload_bytes)
        if self.orig_packet_count and self.resp_packet_count:
            self.tcp_state_flags.add('BIDIR')

    @property
    def observed_tcp_state(self) -> str | None:
        if self.protocol != 'tcp': return None
        if self._handshake: return 'observed_handshake'
        if self._refused: return 'refused_rst'
        if self._syn_seq is not None and self.resp_packet_count == 0: return 'syn_only'
        if self._syn_seq is None: return 'midstream'
        if self.orig_packet_count and self.resp_packet_count: return 'inferred_bidir'
        return 'other'

    def as_dict(self) -> dict:
        flags = set(self.flow_visibility_flags)
        if not self.orig_packet_count or not self.resp_packet_count:
            flags.add('one_way')
        if self.protocol == 'tcp' and not self._handshake:
            flags.add('missing_handshake')
        if self.origin_basis != 'syn_observed':
            flags.add('origin_inferred')
        return dict(flow_id=self.flow_id, conversation_id=self.conversation_id,
                    attempt_ordinal=self.attempt_ordinal, protocol=self.protocol,
                    origin_ip=self.origin_ip, origin_port=self.origin_port,
                    responder_ip=self.responder_ip, responder_port=self.responder_port,
                    origin_basis=self.origin_basis,
                    first_seen_ns=self.first_seen_ns, last_seen_ns=self.last_seen_ns,
                    observed_duration_ns=self.last_seen_ns - self.first_seen_ns,
                    orig_packet_count=self.orig_packet_count, resp_packet_count=self.resp_packet_count,
                    orig_ip_declared_bytes=self.orig_ip_declared_bytes,
                    resp_ip_declared_bytes=self.resp_ip_declared_bytes,
                    orig_ip_captured_bytes=self.orig_ip_captured_bytes,
                    resp_ip_captured_bytes=self.resp_ip_captured_bytes,
                    orig_l4_payload_observed_bytes=self.orig_l4_payload_observed_bytes,
                    resp_l4_payload_observed_bytes=self.resp_l4_payload_observed_bytes,
                    orig_tcp_unique_payload_estimate_bytes=self._orig_unique.size if self.protocol == 'tcp' else None,
                    resp_tcp_unique_payload_estimate_bytes=self._resp_unique.size if self.protocol == 'tcp' else None,
                    observed_tcp_state=self.observed_tcp_state,
                    tcp_state_flags=sorted(self.tcp_state_flags),
                    flow_visibility_flags=sorted(flags),
                    packet_ref_count=self.packet_ref_count,
                    packet_refs_sample=self.packet_refs_sample)


class FlowTracker:
    def __init__(self, capture_id: str, udp_idle_ns: int = 60_000_000_000, tcp_idle_ns: int = 1_800_000_000_000):
        self.capture_id = capture_id
        self.udp_idle_ns = udp_idle_ns
        self.tcp_idle_ns = tcp_idle_ns
        self.conversations: dict[tuple, list[Flow]] = {}
        self.ids: dict[tuple, str] = {}
        self.all_flows: list[Flow] = []

    def add(self, p: Decoded) -> Flow | None:
        if p.ip_protocol not in (6, 17) or p.src_port is None or p.dst_port is None or not p.src_ip or not p.dst_ip:
            return None
        key = conversation_key(p)
        flows = self.conversations.setdefault(key, [])
        conv_id = self.ids.setdefault(key, _id('C-', self.capture_id, key))
        last = flows[-1] if flows else None
        new = last is None
        is_syn = p.ip_protocol == 6 and (p.tcp_flags & SYN) and not (p.tcp_flags & ACK)
        if last:
            gap = p.ts_ns - last._last_file_ts
            if p.ip_protocol == 17:
                new = gap > self.udp_idle_ns
            elif is_syn:
                is_same_syn = (last.origin_ip == p.src_ip and last.origin_port == p.src_port
                               and last._syn_seq == p.tcp_seq and not last._handshake
                               and not last._rst and not (last._fin_orig and last._fin_resp)
                               and gap >= 0 and gap < self.tcp_idle_ns)
                new = not is_same_syn
            else:
                new = gap > self.tcp_idle_ns or (last._rst and gap > 2_000_000_000)
        if new:
            # If first observed packet is SYNACK, infer initiator as destination, but don't claim observed SYN.
            reverse_synack = p.ip_protocol == 6 and (p.tcp_flags & SYN) and (p.tcp_flags & ACK)
            origin_ip = p.dst_ip if reverse_synack else p.src_ip
            origin_port = p.dst_port if reverse_synack else p.src_port
            responder_ip = p.src_ip if reverse_synack else p.dst_ip
            responder_port = p.src_port if reverse_synack else p.dst_port
            basis = 'syn_observed' if is_syn else 'inferred' if reverse_synack else 'first_packet'
            ordinal = len(flows) + 1
            flow = Flow(_id('F-', self.capture_id, key, ordinal), conv_id, ordinal,
                        'tcp' if p.ip_protocol == 6 else 'udp', origin_ip, origin_port,
                        responder_ip, responder_port, basis, p.ts_ns, p.ts_ns)
            if last and not is_syn:
                flow.flow_visibility_flags.add('idle_split_heuristic')
            flows.append(flow)
            self.all_flows.append(flow)
        else:
            flow = last
        flow.add(p)
        return flow
