"""Read-only PCAP observation pipeline: decode -> flows -> disk provenance -> JSON.

This is intentionally NOT an intrusion detection engine yet. GT/IOC files never
enter the runtime. All observed flow-frame links are stored in the SQLite index.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import ipaddress
import json
import sqlite3
from .reader import PcapReader
from .decoders import decode
from .dns_events import DNSMatcher
from .flows import FlowTracker, _id

ENGINE_VERSION = '0.1.0-core'
SCHEMA_VERSION = '0.1.0'


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _json(data) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _make_db(path: Path, overwrite: bool = False) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not overwrite:
            raise FileExistsError(f'Index already exists; choose another path or use --overwrite: {path}')
        path.unlink()
    db = sqlite3.connect(str(path))
    db.executescript('''
    PRAGMA journal_mode=DELETE;
    PRAGMA synchronous=NORMAL;
    CREATE TABLE packets (
        frame_no INTEGER PRIMARY KEY, record_offset INTEGER NOT NULL, ts_ns INTEGER NOT NULL,
        captured_len INTEGER NOT NULL, wire_len INTEGER NOT NULL,
        parse_status TEXT NOT NULL, l2_type TEXT, src_mac TEXT, dst_mac TEXT,
        vlan_tags_json TEXT NOT NULL, ether_type INTEGER,
        ip_version INTEGER, src_ip TEXT, dst_ip TEXT,
        protocol INTEGER, src_port INTEGER, dst_port INTEGER, fragment_state TEXT NOT NULL,
        ip_declared_bytes INTEGER, ip_captured_bytes INTEGER,
        tcp_flags INTEGER, tcp_seq INTEGER, tcp_ack INTEGER, l4_captured_payload_bytes INTEGER,
        issues_json TEXT NOT NULL);
    CREATE TABLE conversations (
        conversation_id TEXT PRIMARY KEY, protocol TEXT NOT NULL,
        endpoint_a_json TEXT NOT NULL, endpoint_b_json TEXT NOT NULL,
        flow_ids_json TEXT NOT NULL);
    CREATE TABLE flow_packets (
        frame_no INTEGER PRIMARY KEY REFERENCES packets(frame_no),
        flow_id TEXT NOT NULL, direction TEXT NOT NULL);
    CREATE TABLE flows (flow_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, data_json TEXT NOT NULL);
    CREATE TABLE events (event_id TEXT PRIMARY KEY, event_kind TEXT NOT NULL,
        packet_frame INTEGER, data_json TEXT NOT NULL);
    CREATE INDEX flow_packet_flow ON flow_packets(flow_id, frame_no);
    CREATE INDEX packet_src ON packets(src_ip, ts_ns);
    CREATE INDEX packet_dst ON packets(dst_ip, ts_ns);
    CREATE INDEX event_kind ON events(event_kind);
    ''')
    return db


def _role(ip: str, networks: list) -> tuple[str, str]:
    address = ipaddress.ip_address(ip)
    if networks:
        return ('configured_local', 'cidr') if any(address in net for net in networks) else ('external', 'cidr')
    if address.is_private or address.is_link_local:
        return 'candidate_local', 'address_heuristic_not_proof'
    return 'unknown', 'no_local_cidrs'


def analyze(path: str | Path, index_path: str | Path, *, max_flows: int = 200,
            max_events: int = 100, local_cidrs: list[str] | None = None,
            udp_idle_sec: float = 60., tcp_idle_sec: float = 1800.,
            overwrite: bool = False) -> dict:
    path = Path(path)
    index_path = Path(index_path)
    if path.resolve() == index_path.resolve():
        raise ValueError('SQLite index path must be different from input PCAP path')
    if max_flows < 0 or max_events < 0:
        raise ValueError('max_flows and max_events must be nonnegative')
    networks = [ipaddress.ip_network(net, strict=False) for net in (local_cidrs or [])]
    filehash = sha256_file(path)
    capture_id = 'CAP-' + filehash[:24]
    if udp_idle_sec <= 0 or tcp_idle_sec <= 0:
        raise ValueError('idle times must be positive')
    tracker = FlowTracker(capture_id, int(udp_idle_sec * 1e9), int(tcp_idle_sec * 1e9))
    dns = DNSMatcher(capture_id)
    count_by_type = Counter()
    count_by_parse = Counter()
    issues = Counter()
    issue_first_frames = {}
    time_reversals = 0
    previous_ts = None
    first = last = None
    packet_count = 0
    arp_total = 0
    icmp_total = 0
    all_arp_examples = []
    all_icmp_examples = []
    # Index every observed frame and each flow association, without storing raw frame bytes.
    # Validate PCAP header before creating or overwriting any output file.
    with PcapReader(path):
        pass
    db = _make_db(index_path, overwrite=overwrite)
    try:
        with PcapReader(path) as reader:
            hdr = reader.header
            for r in reader:
                packet_count += 1
                if previous_ts is not None and r.ts_ns < previous_ts:
                    time_reversals += 1
                previous_ts = r.ts_ns
                first = r.ts_ns if first is None else min(first, r.ts_ns)
                last = r.ts_ns if last is None else max(last, r.ts_ns)
                pkt = decode(r, hdr.linktype)
                count_by_parse[pkt.parse_status] += 1
                if pkt.arp is not None:
                    protocol_label = 'arp'; arp_total += 1
                elif pkt.icmp is not None:
                    protocol_label = 'icmpv6' if pkt.ip_version == 6 else 'icmp'; icmp_total += 1
                elif pkt.ip_protocol == 6:
                    protocol_label = 'tcp'
                elif pkt.ip_protocol == 17:
                    protocol_label = 'udp'
                elif pkt.ip_version == 6:
                    protocol_label = 'ipv6_other'
                elif pkt.ip_version == 4:
                    protocol_label = 'ipv4_other'
                else:
                    protocol_label = pkt.l2_type or 'other'
                count_by_type[protocol_label] += 1
                for flag in pkt.issues:
                    issues[flag] += 1
                    issue_first_frames.setdefault(flag, r.frame_no)
                db.execute('''INSERT INTO packets VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (r.frame_no, r.offset, r.ts_ns, r.captured_len, r.wire_len, pkt.parse_status,
                            pkt.l2_type, pkt.src_mac, pkt.dst_mac, _json(pkt.vlan_tags), pkt.ether_type,
                            pkt.ip_version, pkt.src_ip, pkt.dst_ip, pkt.ip_protocol, pkt.src_port,
                            pkt.dst_port, pkt.fragment_state, pkt.ip_declared_bytes, pkt.ip_captured_bytes,
                            pkt.tcp_flags if pkt.ip_protocol == 6 else None, pkt.tcp_seq, pkt.tcp_ack,
                            pkt.l4_captured_payload_bytes, _json(pkt.issues)))
                flow = tracker.add(pkt)
                if flow is not None:
                    db.execute('INSERT INTO flow_packets VALUES(?,?,?)',
                               (r.frame_no, flow.flow_id, flow.direction(pkt)))
                if pkt.dns is not None:
                    dns.add(pkt)
                if pkt.arp is not None:
                    ev = dict(arp_event_id=_id('ARP-', capture_id, r.frame_no),
                              packet_ref=r.frame_no, ts_ns=r.ts_ns, **pkt.arp)
                    if len(all_arp_examples) < max_events:
                        all_arp_examples.append(ev)
                    db.execute('INSERT INTO events VALUES(?,?,?,?)',
                               (ev['arp_event_id'], 'arp', r.frame_no, _json(ev)))
                if pkt.icmp is not None:
                    ev = dict(icmp_event_id=_id('ICMP-', capture_id, r.frame_no),
                              packet_ref=r.frame_no, ts_ns=r.ts_ns,
                              ip_version=pkt.ip_version, src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                              **pkt.icmp)
                    if len(all_icmp_examples) < max_events:
                        all_icmp_examples.append(ev)
                    db.execute('INSERT INTO events VALUES(?,?,?,?)',
                               (ev['icmp_event_id'], 'icmp', r.frame_no, _json(ev)))
                if packet_count % 5000 == 0:
                    db.commit()
            for w in reader.warnings:
                k = w['code']; issues[k] += 1
                issue_first_frames.setdefault(k, w.get('frame'))
        for key, grouped_flows in tracker.conversations.items():
            db.execute('INSERT INTO conversations VALUES(?,?,?,?,?)',
                       (tracker.ids[key], key[0], _json(key[1]), _json(key[2]),
                        _json([f.flow_id for f in grouped_flows])))
        for flow in tracker.all_flows:
            record = flow.as_dict()
            db.execute('INSERT INTO flows VALUES(?,?,?)',
                       (flow.flow_id, flow.conversation_id, _json(record)))
        for event in dns.events:
            db.execute('INSERT INTO events VALUES(?,?,?,?)',
                       (event['dns_event_id'], 'dns', event['query_packet_ref'] or event['response_packet_ref'], _json(event)))
        db.commit()
    except Exception:
        db.rollback()
        db.close()
        index_path.unlink(missing_ok=True)
        raise
    finally:
        try: db.close()
        except Exception: pass

    hosts = defaultdict(lambda: {'peers': set(), 'ports': set(), 'flow_count': 0, 'dns_query_count': 0})
    for flow in tracker.all_flows:
        host = hosts[flow.origin_ip]
        host['peers'].add(flow.responder_ip)
        host['ports'].add(flow.responder_port)
        host['flow_count'] += 1
    for event in dns.events:
        if event['query_packet_ref'] is not None:
            hosts[event['client_ip']]['dns_query_count'] += 1
    host_profiles = []
    for host_ip, summary in hosts.items():
        role, basis = _role(host_ip, networks)
        host_profiles.append(dict(host_key=host_ip,
                                  address_family='ipv6' if ':' in host_ip else 'ipv4',
                                  network_role=role, network_role_basis=basis,
                                  unique_destination_ip_count=len(summary['peers']),
                                  unique_destination_port_count=len(summary['ports']),
                                  observed_flow_count=summary['flow_count'],
                                  observed_dns_query_count=summary['dns_query_count']))
    host_profiles.sort(key=lambda d: (ipaddress.ip_address(d['host_key']).version,
                                       int(ipaddress.ip_address(d['host_key']))))
    all_flows = sorted(tracker.all_flows, key=lambda f: (f.first_seen_ns, f.flow_id))
    tcp_states = Counter(f.observed_tcp_state for f in all_flows if f.protocol == 'tcp')
    dns_states = Counter(ev['match_status'] for ev in dns.events)
    matched_nxdomain = sum(1 for ev in dns.events if ev['match_status'] == 'matched' and ev['rcode'] == 3)
    warnings = [{'code': code, 'count': count, 'first_frame': issue_first_frames.get(code)}
                for code, count in sorted(issues.items())]
    if time_reversals:
        warnings.append({'code': 'timestamp_file_order_reversal', 'count': time_reversals})
    if packet_count == 0:
        warnings.append({'code': 'empty_capture', 'count': 1})
    if first is not None and last - first < 30_000_000_000:
        warnings.append({'code': 'short_capture_limits_temporal_analysis', 'observed_span_ns': last - first})
    if hdr.linktype not in (1, 101, 113):
        warnings.append({'code': 'unsupported_linktype', 'linktype': hdr.linktype})
    capture = dict(capture_id=capture_id, source_path=str(path), sha256=filehash,
                   file_size_bytes=path.stat().st_size,
                   format_version=f'{hdr.version_major}.{hdr.version_minor}',
                   byte_order=hdr.byte_order, ts_precision=hdr.precision,
                   snaplen=hdr.snaplen, linktype=hdr.linktype,
                   packet_count=packet_count, first_ts_ns=first, last_ts_ns=last,
                   observed_span_ns=last - first if first is not None else None,
                   parse_warnings=warnings)
    return dict(schema_version=SCHEMA_VERSION, engine_version=ENGINE_VERSION,
                stage='observation_core_only_no_detectors', capture=capture,
                summary=dict(packet_types=dict(sorted(count_by_type.items())),
                             parse_status=dict(sorted(count_by_parse.items())),
                             conversation_count=len(tracker.conversations),
                             flow_count=len(all_flows),
                             tcp_state_counts=dict(sorted(tcp_states.items())),
                             dns_transaction_count=len(dns.events),
                             dns_match_status=dict(sorted(dns_states.items())),
                             observed_matched_nxdomain_count=matched_nxdomain,
                             arp_event_count=arp_total, icmp_event_count=icmp_total,
                             host_profile_count=len(host_profiles)),
                flows=[f.as_dict() for f in all_flows[:max_flows]],
                flow_results_truncated=len(all_flows) > max_flows,
                dns_events=dns.events[:max_events],
                dns_events_truncated=len(dns.events) > max_events,
                arp_events=all_arp_examples, arp_events_truncated=arp_total > max_events,
                icmp_events=all_icmp_examples, icmp_events_truncated=icmp_total > max_events,
                host_profiles=host_profiles[:max_flows],
                host_profiles_truncated=len(host_profiles) > max_flows,
                full_provenance_index=str(index_path),
                detectors_status='not_implemented', detector_evaluations=[], evidence=[], findings=[])
