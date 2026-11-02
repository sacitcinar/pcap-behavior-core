"""Bounded, standard-library L2/L3/L4/DNS protocol decoders.

No IP reassembly, TCP stream reassembly, checksum verification or TLS decryption.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import ipaddress
from .reader import Record

class DecodeError(Exception):
    pass

@dataclass(slots=True)
class DNSMessage:
    transaction_id: int
    is_response: bool
    qname: str | None
    qtype: int | None
    rcode: int | None
    answer_ips: list[str] = field(default_factory=list)
    status: str = 'ok'

@dataclass(slots=True)
class Decoded:
    frame_no: int
    ts_ns: int
    record_offset: int
    captured_len: int
    wire_len: int
    l2_type: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    vlan_tags: list[int] = field(default_factory=list)
    ether_type: int | None = None
    ip_version: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_protocol: int | None = None
    ip_declared_bytes: int | None = None
    ip_captured_bytes: int | None = None
    fragment_state: str = 'unfragmented'
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int = 0
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    l4_captured_payload_bytes: int | None = None
    payload: bytes = b''
    dns: DNSMessage | None = None
    arp: dict | None = None
    icmp: dict | None = None
    parse_status: str = 'ok'
    issues: list[str] = field(default_factory=list)


def _mac(raw: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in raw)


def _read_name(msg: bytes, start: int) -> tuple[str, int]:
    labels = []
    pos = start
    next_pos = None
    visited = set()
    for _ in range(64):
        if pos >= len(msg):
            raise DecodeError('dns_name_truncated')
        if pos in visited:
            raise DecodeError('dns_compression_loop')
        visited.add(pos)
        size = msg[pos]
        if (size & 0xc0) == 0xc0:
            if pos + 1 >= len(msg):
                raise DecodeError('dns_pointer_truncated')
            pointer = ((size & 0x3f) << 8) | msg[pos + 1]
            if pointer >= len(msg):
                raise DecodeError('dns_pointer_out_of_range')
            if next_pos is None:
                next_pos = pos + 2
            pos = pointer
            continue
        if size & 0xc0:
            raise DecodeError('dns_invalid_label_type')
        pos += 1
        if size == 0:
            wire = '.'.join(labels)
            if len(wire) > 253:
                raise DecodeError('dns_name_too_long')
            return wire.lower(), (pos if next_pos is None else next_pos)
        if size > 63 or pos + size > len(msg):
            raise DecodeError('dns_label_truncated')
        label = msg[pos:pos + size]
        # DNS wire identity is bytes, not necessarily valid UTF8.
        labels.append(''.join(chr(c) if 33 <= c <= 126 and chr(c) not in ('.', '\\') else f'\\x{c:02x}' for c in label))
        pos += size
    raise DecodeError('dns_name_depth_exceeded')


def parse_dns(raw: bytes) -> DNSMessage:
    if len(raw) < 12:
        raise DecodeError('dns_header_truncated')
    qid = int.from_bytes(raw[0:2], 'big')
    flags = int.from_bytes(raw[2:4], 'big')
    qd = int.from_bytes(raw[4:6], 'big')
    an = int.from_bytes(raw[6:8], 'big')
    qr = bool(flags & 0x8000)
    message = DNSMessage(qid, qr, None, None, (flags & 0x0f) if qr else None)
    if qd > 64 or an > 1000:
        raise DecodeError('dns_record_count_limit')
    offset = 12
    for i in range(qd):
        name, offset = _read_name(raw, offset)
        if offset + 4 > len(raw):
            raise DecodeError('dns_question_truncated')
        typ = int.from_bytes(raw[offset:offset + 2], 'big')
        offset += 4
        if i == 0:
            message.qname, message.qtype = name, typ
    if qd != 1:
        message.status = 'partial'  # Preserve first question, but do not treat as unambiguous transaction.
    answer_records = []
    for _ in range(an):
        owner, offset = _read_name(raw, offset)
        if offset + 10 > len(raw):
            raise DecodeError('dns_rr_header_truncated')
        typ = int.from_bytes(raw[offset:offset + 2], 'big')
        cls = int.from_bytes(raw[offset + 2:offset + 4], 'big')
        n = int.from_bytes(raw[offset + 8:offset + 10], 'big')
        offset += 10
        if offset + n > len(raw):
            raise DecodeError('dns_rr_data_truncated')
        if cls == 1 and ((typ == 1 and n == 4) or (typ == 28 and n == 16)):
            answer_records.append((owner, typ, str(ipaddress.ip_address(raw[offset:offset + n]))))
        elif cls == 1 and typ == 5:  # DNS CNAME; follow only aliases for the queried name.
            alias, end = _read_name(raw, offset)
            if end != offset + n:
                raise DecodeError('dns_cname_rdata_length_invalid')
            answer_records.append((owner, typ, alias))
        offset += n
    # An answer section can contain records for names unrelated to the query.
    # Do not attribute their addresses to this host's requested name. Accept
    # CNAME -> A/AAAA chains independent of RR ordering, with bounded depth.
    reachable = {message.qname} if message.qname else set()
    for _ in range(64):
        aliases = {value for owner, typ, value in answer_records
                   if typ == 5 and owner in reachable}
        if aliases <= reachable:
            break
        reachable.update(aliases)
    message.answer_ips = [value for owner, typ, value in answer_records
                          if typ in (1, 28) and owner in reachable]
    return message


def decode(record: Record, linktype: int) -> Decoded:
    p = Decoded(record.frame_no, record.ts_ns, record.offset, record.captured_len, record.wire_len)
    raw = record.raw
    try:
        if linktype == 1:  # Ethernet
            p.l2_type = 'ethernet'
            if len(raw) < 14:
                raise DecodeError('ethernet_header_truncated')
            p.dst_mac, p.src_mac = _mac(raw[:6]), _mac(raw[6:12])
            eth = int.from_bytes(raw[12:14], 'big')
            start = 14
            while eth in (0x8100, 0x88a8, 0x9100):
                if len(p.vlan_tags) >= 8:
                    raise DecodeError('too_many_vlan_tags')
                if start + 4 > len(raw):
                    raise DecodeError('vlan_header_truncated')
                p.vlan_tags.append(int.from_bytes(raw[start:start + 2], 'big') & 0xfff)
                eth = int.from_bytes(raw[start + 2:start + 4], 'big')
                start += 4
        elif linktype == 101:  # DLT_RAW
            p.l2_type = 'raw_ip'
            if not raw:
                raise DecodeError('raw_ip_empty')
            eth = 0x0800 if raw[0] >> 4 == 4 else 0x86dd if raw[0] >> 4 == 6 else 0
            start = 0
        elif linktype == 113:  # Linux cooked v1, 16-byte header
            p.l2_type = 'linux_sll'
            if len(raw) < 16:
                raise DecodeError('linux_sll_header_truncated')
            eth = int.from_bytes(raw[14:16], 'big')
            start = 16
        else:
            p.l2_type = 'unsupported'
            p.parse_status = 'unsupported'
            p.issues.append('unsupported_dlt')
            return p
        p.ether_type = eth
        if eth == 0x0800:
            _ipv4(p, raw[start:])
        elif eth == 0x86dd:
            _ipv6(p, raw[start:])
        elif eth == 0x0806:
            _arp(p, raw[start:])
        else:
            p.parse_status = 'unsupported'
            p.issues.append('unsupported_ethertype')
        return p
    except DecodeError as exc:
        p.parse_status = 'partial' if any(token in str(exc) for token in ('truncated', 'limit')) else 'malformed'
        p.issues.append(str(exc))
        return p


def _ipv4(p: Decoded, raw: bytes) -> None:
    if len(raw) < 20:
        raise DecodeError('ipv4_header_truncated')
    if raw[0] >> 4 != 4:
        raise DecodeError('ipv4_version_invalid')
    ihl = (raw[0] & 0xf) * 4
    if ihl < 20 or len(raw) < ihl:
        raise DecodeError('ipv4_ihl_invalid_or_truncated')
    declared = int.from_bytes(raw[2:4], 'big')
    if declared < ihl:
        raise DecodeError('ipv4_total_length_invalid')
    p.ip_version = 4
    p.src_ip = str(ipaddress.IPv4Address(raw[12:16]))
    p.dst_ip = str(ipaddress.IPv4Address(raw[16:20]))
    p.ip_protocol = raw[9]
    p.ip_declared_bytes = declared
    p.ip_captured_bytes = min(len(raw), declared)
    if len(raw) < declared:
        p.issues.append('ip_snaplen_or_truncation')
        p.parse_status = 'partial'
    flags_offset = int.from_bytes(raw[6:8], 'big')
    frag_offset = flags_offset & 0x1fff
    more = bool(flags_offset & 0x2000)
    if frag_offset:
        p.fragment_state = 'nonfirst'
        p.issues.append('fragment_no_reassembly')
        return
    if more:
        p.fragment_state = 'first'
        p.issues.append('fragment_no_reassembly')
    _transport(p, raw[ihl:min(len(raw), declared)])


def _ipv6(p: Decoded, raw: bytes) -> None:
    if len(raw) < 40:
        raise DecodeError('ipv6_header_truncated')
    if raw[0] >> 4 != 6:
        raise DecodeError('ipv6_version_invalid')
    declared_payload = int.from_bytes(raw[4:6], 'big')
    if not declared_payload:
        p.issues.append('ipv6_zero_payload_or_jumbogram_unsupported')
    declared = 40 + declared_payload
    p.ip_version = 6
    p.src_ip = str(ipaddress.IPv6Address(raw[8:24]))
    p.dst_ip = str(ipaddress.IPv6Address(raw[24:40]))
    p.ip_declared_bytes = declared if declared_payload else None
    p.ip_captured_bytes = min(len(raw), declared) if declared_payload else len(raw)
    if declared_payload and len(raw) < declared:
        p.parse_status = 'partial'
        p.issues.append('ip_snaplen_or_truncation')
    next_header = raw[6]
    pos = 40
    end = min(len(raw), declared) if declared_payload else len(raw)
    for _ in range(12):
        if next_header in (0, 43, 60, 135):  # Hop-by-hop, routing, destination, mobility
            if pos + 2 > end:
                raise DecodeError('ipv6_extension_truncated')
            new_next = raw[pos]
            length = (raw[pos + 1] + 1) * 8
            if pos + length > end:
                raise DecodeError('ipv6_extension_truncated')
            pos += length
            next_header = new_next
        elif next_header == 44:  # Fragment
            if pos + 8 > end:
                raise DecodeError('ipv6_fragment_truncated')
            new_next = raw[pos]
            field = int.from_bytes(raw[pos + 2:pos + 4], 'big')
            offset = (field >> 3) & 0x1fff
            more = bool(field & 1)
            pos += 8
            next_header = new_next
            if offset:
                p.fragment_state = 'nonfirst'
                p.ip_protocol = next_header
                p.issues.append('fragment_no_reassembly')
                return
            p.fragment_state = 'first' if more else 'atomic'
            if more:
                p.issues.append('fragment_no_reassembly')
        elif next_header == 51:  # AH
            if pos + 2 > end:
                raise DecodeError('ipv6_ah_truncated')
            new_next = raw[pos]
            length = (raw[pos + 1] + 2) * 4
            if pos + length > end:
                raise DecodeError('ipv6_ah_truncated')
            pos += length
            next_header = new_next
        else:
            break
    else:
        raise DecodeError('ipv6_extension_depth_limit')
    p.ip_protocol = next_header
    if next_header in (50, 59):  # ESP, no next header
        p.parse_status = 'unsupported'
        return
    _transport(p, raw[pos:end])


def _transport(p: Decoded, raw: bytes) -> None:
    proto = p.ip_protocol
    if proto == 6:
        if len(raw) < 20:
            raise DecodeError('tcp_header_truncated')
        header_size = (raw[12] >> 4) * 4
        if header_size < 20:
            raise DecodeError('tcp_header_length_invalid')
        if len(raw) < header_size:
            raise DecodeError('tcp_options_truncated')
        p.src_port = int.from_bytes(raw[:2], 'big')
        p.dst_port = int.from_bytes(raw[2:4], 'big')
        p.tcp_seq = int.from_bytes(raw[4:8], 'big')
        p.tcp_ack = int.from_bytes(raw[8:12], 'big')
        p.tcp_flags = ((raw[12] & 1) << 8) | raw[13]
        p.payload = raw[header_size:]
        p.l4_captured_payload_bytes = len(p.payload)
    elif proto == 17:
        if len(raw) < 8:
            raise DecodeError('udp_header_truncated')
        length = int.from_bytes(raw[4:6], 'big')
        if length < 8 and not (p.ip_version == 6 and length == 0):
            raise DecodeError('udp_length_invalid')
        p.src_port = int.from_bytes(raw[:2], 'big')
        p.dst_port = int.from_bytes(raw[2:4], 'big')
        upper = len(raw) if length == 0 else min(length, len(raw))
        if length and length > len(raw):
            p.parse_status = 'partial'
            p.issues.append('udp_payload_truncated')
        p.payload = raw[8:upper]
        p.l4_captured_payload_bytes = len(p.payload)
        if (p.src_port == 53 or p.dst_port == 53) and p.fragment_state in ('unfragmented', 'atomic'):
            try:
                p.dns = parse_dns(p.payload)
            except DecodeError as exc:
                p.issues.append(str(exc))
                p.parse_status = 'partial'
    elif (p.ip_version == 4 and proto == 1) or (p.ip_version == 6 and proto == 58):
        if len(raw) < 4:
            raise DecodeError('icmp_header_truncated')
        typ, code = raw[0], raw[1]
        echo = typ in ((8, 0) if p.ip_version == 4 else (128, 129))
        p.icmp = {'type': typ, 'code': code,
                  'echo_identifier': int.from_bytes(raw[4:6], 'big') if echo and len(raw) >= 8 else None,
                  'echo_sequence': int.from_bytes(raw[6:8], 'big') if echo and len(raw) >= 8 else None}


def _arp(p: Decoded, raw: bytes) -> None:
    if len(raw) < 8:
        raise DecodeError('arp_header_truncated')
    htype = int.from_bytes(raw[:2], 'big')
    ptype = int.from_bytes(raw[2:4], 'big')
    hlen, plen = raw[4], raw[5]
    op = int.from_bytes(raw[6:8], 'big')
    if hlen > 32 or plen > 16 or 8 + 2 * (hlen + plen) > len(raw):
        raise DecodeError('arp_body_truncated')
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        p.parse_status = 'unsupported'
        p.issues.append('arp_non_ethernet_ipv4')
        return
    at = 8
    sha = _mac(raw[at:at + 6]); at += 6
    spa = str(ipaddress.IPv4Address(raw[at:at + 4])); at += 4
    tha = _mac(raw[at:at + 6]); at += 6
    tpa = str(ipaddress.IPv4Address(raw[at:at + 4]))
    kind = 'probe' if spa == '0.0.0.0' and op == 1 else 'gratuitous' if spa == tpa else 'request' if op == 1 else 'reply' if op == 2 else 'other'
    p.arp = {'operation': op, 'sender_mac': sha, 'sender_ip': spa,
             'target_mac': tha, 'target_ip': tpa, 'arp_kind': kind}
