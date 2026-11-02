"""Conservative DNS query/response matching, never invent NXDOMAIN."""
from __future__ import annotations
from collections import defaultdict
from .decoders import Decoded
from .flows import _id

class DNSMatcher:
    def __init__(self, capture_id: str, max_response_delay_ns: int = 60_000_000_000):
        self.capture_id = capture_id
        self.max_response_delay_ns = max_response_delay_ns
        self.events: list[dict] = []
        self.pending: dict[tuple, list[int]] = defaultdict(list)
        self.response_only = 0

    def add(self, p: Decoded):
        msg = p.dns
        if msg is None or p.src_port is None or p.dst_port is None or not p.src_ip or not p.dst_ip:
            return
        if msg.qname is None or msg.qtype is None or msg.status != 'ok':
            return  # Multi-question messages are not unambiguously matchable.
        if msg.is_response:
            key = (p.dst_ip, p.dst_port, p.src_ip, p.src_port, msg.transaction_id, msg.qname, msg.qtype)
            candidates = self.pending.pop(key, [])
            # DNS ID alone is never enough: reject responses outside the
            # configured latency horizon or before the observed query.
            eligible = [i for i in candidates
                        if 0 <= p.ts_ns - self.events[i]['query_ts_ns'] <= self.max_response_delay_ns]
            if len(eligible) == 1:
                event = self.events[eligible[0]]
                event['response_packet_ref'] = p.frame_no
                event['response_ts_ns'] = p.ts_ns
                event['rcode'] = msg.rcode
                event['answer_ip_addresses'] = msg.answer_ips
                event['match_status'] = 'matched'
            elif len(eligible) > 1:
                for idx in eligible:
                    self.events[idx]['match_status'] = 'ambiguous'
                self._response_only(p, 'ambiguous')
            else:
                self._response_only(p, 'response_only')
            return
        event = dict(
            dns_event_id=_id('DNS-', self.capture_id, p.frame_no, 0),
            query_packet_ref=p.frame_no, response_packet_ref=None,
            query_ts_ns=p.ts_ns, response_ts_ns=None,
            client_ip=p.src_ip, client_port=p.src_port,
            resolver_ip=p.dst_ip, resolver_port=p.dst_port,
            qname_normalized=msg.qname, qtype=msg.qtype,
            transaction_id=msg.transaction_id, rcode=None,
            answer_ip_addresses=[], match_status='unanswered')
        idx = len(self.events)
        self.events.append(event)
        key = (p.src_ip, p.src_port, p.dst_ip, p.dst_port, msg.transaction_id, msg.qname, msg.qtype)
        self.pending[key].append(idx)

    def _response_only(self, p: Decoded, status: str):
        m = p.dns
        self.response_only += 1
        self.events.append(dict(
            dns_event_id=_id('DNS-R-', self.capture_id, p.frame_no, 0),
            query_packet_ref=None, response_packet_ref=p.frame_no,
            query_ts_ns=None, response_ts_ns=p.ts_ns,
            client_ip=p.dst_ip, client_port=p.dst_port,
            resolver_ip=p.src_ip, resolver_port=p.src_port,
            qname_normalized=m.qname, qtype=m.qtype,
            transaction_id=m.transaction_id, rcode=m.rcode,
            answer_ip_addresses=m.answer_ips, match_status=status))
