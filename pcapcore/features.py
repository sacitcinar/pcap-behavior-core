"""Evidence-ready *observations*, not detections, from the core SQLite index.

All measurements are capture-local. No IOC or ground-truth files are loaded.
The feature store retains the indexed packet and flow observations without
modifying their original measurements.
"""
from __future__ import annotations

from bisect import insort
from collections import Counter, defaultdict
from ipaddress import ip_address, ip_network
import json
from pathlib import Path
import sqlite3
import statistics
from typing import Iterable

from .flows import _id

FEATURE_VERSION = '0.2.0-features'
NS = 1_000_000_000


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def _median(data: list[int]) -> int | float | None:
    return statistics.median(data) if data else None


def _qlinear(sorted_values: list[int], probability: float) -> float | None:
    """Hyndman/Fan type 7 (linear interpolation) quartiles, documented and fixed."""
    if not sorted_values:
        return None
    rank = (len(sorted_values) - 1) * probability
    lo = int(rank)
    fraction = rank - lo
    return sorted_values[lo] + fraction * (sorted_values[min(lo + 1, len(sorted_values) - 1)] - sorted_values[lo])


def _distribution(values: Iterable[int]) -> dict:
    data = sorted(values)
    if not data:
        return dict(sample_count=0, median=None, mad=None, bowley_skewness=None,
                    min=None, max=None)
    midpoint = statistics.median(data)
    mad = statistics.median(abs(x - midpoint) for x in data)
    q1, q2, q3 = (_qlinear(data, p) for p in (0.25, 0.5, 0.75))
    skew = 0.0 if q1 == q3 else (q3 + q1 - 2 * q2) / (q3 - q1)
    return dict(sample_count=len(data), median=midpoint, mad=mad, bowley_skewness=skew,
                min=data[0], max=data[-1])


def _feature_schema(db: sqlite3.Connection) -> None:
    db.executescript('''
        CREATE TABLE IF NOT EXISTS feature_run (
            feature_version TEXT PRIMARY KEY, capture_id TEXT NOT NULL, parameters_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS feature_groups (
            group_id TEXT PRIMARY KEY, subject_json TEXT NOT NULL, metrics_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS feature_group_flows (
            group_id TEXT NOT NULL, flow_id TEXT NOT NULL,
            PRIMARY KEY(group_id, flow_id));
        CREATE TABLE IF NOT EXISTS feature_group_buckets (
            group_id TEXT NOT NULL, window_seconds INTEGER NOT NULL,
            bucket_index INTEGER NOT NULL, flow_starts INTEGER NOT NULL,
            PRIMARY KEY(group_id, window_seconds, bucket_index));
        CREATE TABLE IF NOT EXISTS feature_windows (
            window_id TEXT PRIMARY KEY, kind TEXT NOT NULL,
            subject_json TEXT NOT NULL, metrics_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS feature_window_flows (
            window_id TEXT NOT NULL, flow_id TEXT NOT NULL,
            PRIMARY KEY(window_id, flow_id));
        CREATE TABLE IF NOT EXISTS feature_hosts (
            host_ip TEXT PRIMARY KEY, metrics_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS feature_dns_clients (
            client_ip TEXT PRIMARY KEY, metrics_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS feature_arp_bindings (
            ip TEXT PRIMARY KEY, metrics_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS feature_icmp_hosts (
            host_ip TEXT PRIMARY KEY, metrics_json TEXT NOT NULL);
    ''')


def _counts(data: dict) -> dict:
    return {str(k): v for k, v in sorted(data.items(), key=lambda pair: str(pair[0]))}


def extract_features(index_path: str | Path, capture: dict, *,
                     local_cidrs: list[str] | None = None,
                     windows_sec: tuple[int, ...] = (60, 300),
                     max_json_groups: int = 20, max_json_windows: int = 20,
                     max_json_hosts: int = 20) -> dict:
    """Persist full features in SQLite, return bounded deterministic JSON preview.

    The index must originate from pcapcore.engine.analyze.  A run is not silently
    overwritten; regenerating features with new settings requires a new index.
    """
    if any(v < 0 for v in (max_json_groups, max_json_windows, max_json_hosts)):
        raise ValueError('JSON preview limits must be non-negative')
    if not windows_sec or any(not isinstance(w, int) or isinstance(w, bool) or w <= 0 for w in windows_sec):
        raise ValueError('Window sizes must be positive integers')
    windows_sec = tuple(sorted(set(windows_sec)))
    nets = tuple(ip_network(x, strict=False) for x in (local_cidrs or []))
    capture_id = capture['capture_id']
    anchor = capture['first_ts_ns']
    global_last = capture['last_ts_ns']
    parameters = dict(windows_sec=list(windows_sec),
                      configured_local_cidrs=[str(n) for n in nets],
                      quartile_method='linear_type7',
                      group_key='origin_ip,responder_ip,protocol,responder_port',
                      timing_min_distinct_starts=4)

    db = sqlite3.connect(str(index_path))
    db.row_factory = sqlite3.Row
    try:
        # A feature extraction should never replace a previous completed run.
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='feature_run'").fetchone()
        if exists and db.execute('SELECT 1 FROM feature_run LIMIT 1').fetchone():
            raise FileExistsError('Feature store already exists; create a new observation index')
        _feature_schema(db)
        db.execute('INSERT INTO feature_run VALUES(?,?,?)',
                   (FEATURE_VERSION, capture_id, _json(parameters)))

        flows = [json.loads(row[0]) for row in db.execute('SELECT data_json FROM flows ORDER BY flow_id')]
        # The canonical flow origin is not guaranteed when SYN was not observed.
        groups: dict[tuple, list[dict]] = defaultdict(list)
        hosts: dict[str, dict] = {}
        # Keep a single origin's feature windows in memory at a time.
        # This preserves original per-flow ordering while avoiding 600k+ resident
        # dictionaries on high-cardinality captures.
        flows_by_origin: dict[str, list[dict]] = defaultdict(list)

        for flow in flows:
            ip = flow['origin_ip']
            peer = flow['responder_ip']
            proto = flow['protocol']
            destport = flow['responder_port']
            subject = (ip, peer, proto, destport)
            groups[subject].append(flow)
            flows_by_origin[ip].append(flow)
            if ip not in hosts:
                hosts[ip] = dict(unique_destination_ips=set(), unique_destination_ports=set(),
                                 flow_count=0, protocol_counts=Counter(),
                                 tcp_states=Counter(), packets_orig=0, packets_resp=0,
                                 orig_declared_ip_bytes=0, resp_declared_ip_bytes=0,
                                 orig_observed_l4_bytes=0, resp_observed_l4_bytes=0,
                                 origin_inferred_count=0, visibility_flags=Counter(),
                                 first_seen_ns=None, last_seen_ns=None)
            h = hosts[ip]
            h['unique_destination_ips'].add(peer)
            h['unique_destination_ports'].add((proto, destport))
            h['flow_count'] += 1
            h['protocol_counts'][proto] += 1
            if flow['observed_tcp_state']:
                h['tcp_states'][flow['observed_tcp_state']] += 1
            h['packets_orig'] += flow['orig_packet_count']
            h['packets_resp'] += flow['resp_packet_count']
            h['orig_declared_ip_bytes'] += flow['orig_ip_declared_bytes']
            h['resp_declared_ip_bytes'] += flow['resp_ip_declared_bytes']
            h['orig_observed_l4_bytes'] += flow['orig_l4_payload_observed_bytes']
            h['resp_observed_l4_bytes'] += flow['resp_l4_payload_observed_bytes']
            h['origin_inferred_count'] += flow['origin_basis'] != 'syn_observed'
            h['visibility_flags'].update(flow['flow_visibility_flags'])
            h['first_seen_ns'] = min(h['first_seen_ns'], flow['first_seen_ns']) if h['first_seen_ns'] is not None else flow['first_seen_ns']
            h['last_seen_ns'] = max(h['last_seen_ns'], flow['last_seen_ns']) if h['last_seen_ns'] is not None else flow['last_seen_ns']


        prevalence_sources: dict[tuple, set[str]] = defaultdict(set)
        # Prevalence is local-capture ONLY. When local CIDRs are unspecified it is not computed.
        for (ip, peer, proto, port) in groups:
            if nets and any(ip_address(ip) in net for net in nets):
                prevalence_sources[(peer, proto, port)].add(ip)

        group_preview = []
        total_group_flows = 0
        insufficient_groups = 0
        group_rows: list[tuple] = []
        group_flow_rows: list[tuple] = []
        group_bucket_rows: list[tuple] = []
        def flush_groups() -> None:
            if group_rows:
                db.executemany('INSERT INTO feature_groups VALUES(?,?,?)', group_rows)
                group_rows.clear()
            if group_flow_rows:
                db.executemany('INSERT INTO feature_group_flows VALUES(?,?)', group_flow_rows)
                group_flow_rows.clear()
            if group_bucket_rows:
                db.executemany('INSERT INTO feature_group_buckets VALUES(?,?,?,?)', group_bucket_rows)
                group_bucket_rows.clear()
        for (ip, peer, proto, port), members in sorted(groups.items()):
            group_id = _id('FG-', capture_id, ip, peer, proto, port)
            members.sort(key=lambda f: (f['first_seen_ns'], f['flow_id']))
            times = [f['first_seen_ns'] for f in members]
            distinct = len(set(times))
            intervals = [b - a for a, b in zip(times, times[1:])]
            distribution = _distribution(intervals)
            status = 'available' if distinct >= 4 else 'insufficient_distinct_starts'
            insufficient_groups += status != 'available'
            durations = [f['observed_duration_ns'] for f in members]
            group_flags = Counter(flag for f in members for flag in f['flow_visibility_flags'])
            subject = dict(origin_ip=ip, responder_ip=peer, protocol=proto, responder_port=port)
            metrics = dict(flow_count=len(members), distinct_start_count=distinct,
                           first_start_ns=times[0], last_start_ns=times[-1],
                           timestamp_intervals_ns_sample=intervals[:32],
                           timestamp_intervals_total=len(intervals),
                           timestamp_intervals_sample_truncated=len(intervals)>32,
                           interarrival_distribution=distribution,
                           timing_feature_status=status,
                           observed_duration_total_ns=sum(durations),
                           observed_duration_longest_ns=max(durations),
                           orig_l4_bytes_distribution=_distribution(f['orig_l4_payload_observed_bytes'] for f in members),
                           resp_l4_bytes_distribution=_distribution(f['resp_l4_payload_observed_bytes'] for f in members),
                           orig_ip_declared_bytes_distribution=_distribution(f['orig_ip_declared_bytes'] for f in members),
                           resp_ip_declared_bytes_distribution=_distribution(f['resp_ip_declared_bytes'] for f in members),
                           orientation_not_syn_confirmed_count=sum(f['origin_basis'] != 'syn_observed' for f in members),
                           tcp_without_observed_syn_count=sum(f['protocol'] == 'tcp' and f['origin_basis'] != 'syn_observed' for f in members),
                           visibility_flag_occurrences=_counts(group_flags),
                           local_target_prevalence_count=(len(prevalence_sources[(peer,proto,port)]) if nets else None),
                           local_target_prevalence_status=('capture_only' if nets else 'unavailable_no_local_cidrs'))
            group_rows.append((group_id, _json(subject), _json(metrics)))
            group_flow_rows.extend((group_id, f['flow_id']) for f in members)
            for sec in windows_sec:
                hist = Counter((t - anchor)//(sec*NS) for t in times)
                group_bucket_rows.extend((group_id, sec, idx, count) for idx,count in sorted(hist.items()))
            if len(group_rows) >= 2048 or len(group_flow_rows) >= 8192 or len(group_bucket_rows) >= 8192:
                flush_groups()
            total_group_flows += len(members)
            if len(group_preview) < max_json_groups:
                group_preview.append(dict(group_id=group_id, subject=subject, metrics=metrics))

        flush_groups()
        # A window key always contains its origin IP.  Build and discard windows
        # origin-by-origin instead of materializing all 621k windows at once.
        # Because source flows are still ordered by flow_id, flow_ids_sample and
        # Window-to-flow references retain the normalized flow structure.
        window_counts = Counter()
        window_preview_entries: list[tuple[tuple, dict]] = []
        window_rows: list[tuple] = []
        window_flow_rows: list[tuple] = []

        def flush_windows() -> None:
            if window_rows:
                db.executemany('INSERT INTO feature_windows VALUES(?,?,?,?)', window_rows)
                window_rows.clear()
            if window_flow_rows:
                db.executemany('INSERT INTO feature_window_flows VALUES(?,?)',window_flow_rows)
                window_flow_rows.clear()

        for origin_ip in sorted(flows_by_origin):
            window_data: dict[tuple, dict] = {}
            def wstats(kind: str, subject: tuple, window_size: int, index: int) -> dict:
                k = (kind, subject, window_size, index)
                if k not in window_data:
                    window_data[k] = dict(flow_ids=[], unique_ips=set(), unique_ports=set(),
                                          refused_rst_count=0, syn_only_count=0,
                                          orientation_not_syn_count=0, tcp_without_syn_count=0)
                return window_data[k]

            for flow in flows_by_origin[origin_ip]:
                ip, peer, proto, destport = (flow['origin_ip'],flow['responder_ip'],
                                             flow['protocol'],flow['responder_port'])
                for seconds in windows_sec:
                    i = (flow['first_seen_ns'] - anchor) // (seconds * NS) if anchor is not None else 0
                    for kind, key in [('starts', (ip, proto)),
                                      ('vertical', (ip, peer, proto)),
                                      ('horizontal', (ip, destport, proto))]:
                        stats = wstats(kind, key, seconds, i)
                        stats['flow_ids'].append(flow['flow_id'])
                        stats['unique_ips'].add(peer)
                        stats['unique_ports'].add(destport)
                        stats['refused_rst_count'] += flow['observed_tcp_state'] == 'refused_rst'
                        stats['syn_only_count'] += flow['observed_tcp_state'] == 'syn_only'
                        stats['orientation_not_syn_count'] += flow['origin_basis'] != 'syn_observed'
                        stats['tcp_without_syn_count'] += proto == 'tcp' and flow['origin_basis'] != 'syn_observed'

            for (kind, subject, seconds, idx), w in sorted(window_data.items()):
                win_id = _id('FW-', capture_id, kind, subject, seconds, idx)
                start_ns = anchor + idx * seconds*NS
                metrics = dict(window_seconds=seconds, window_index=idx,
                               window_start_ns=start_ns,
                               window_end_ns=start_ns+seconds*NS,
                               flow_starts=len(w['flow_ids']),
                               unique_responder_ips=len(w['unique_ips']),
                               unique_responder_ports=len(w['unique_ports']),
                               refused_rst_flow_count=w['refused_rst_count'],
                               syn_only_flow_count=w['syn_only_count'],
                               orientation_not_syn_confirmed_count=w['orientation_not_syn_count'],
                               tcp_without_observed_syn_count=w['tcp_without_syn_count'],
                               flow_ids_sample=w['flow_ids'][:12],
                               flow_ids_sample_truncated=len(w['flow_ids'])>12)
                if kind == 'starts':
                    sub = dict(origin_ip=subject[0], protocol=subject[1])
                elif kind == 'vertical':
                    sub = dict(origin_ip=subject[0], responder_ip=subject[1], protocol=subject[2])
                else:
                    sub = dict(origin_ip=subject[0], responder_port=subject[1], protocol=subject[2])
                window_rows.append((win_id,kind,_json(sub),_json(metrics)))
                window_flow_rows.extend((win_id,flow_id) for flow_id in w['flow_ids'])
                window_counts[kind] += 1
                if max_json_windows:
                    key=(kind,subject,seconds,idx)
                    if len(window_preview_entries) < max_json_windows or key < window_preview_entries[-1][0]:
                        insort(window_preview_entries,(key,dict(window_id=win_id, kind=kind, subject=sub, metrics=metrics)))
                        if len(window_preview_entries)>max_json_windows:
                            window_preview_entries.pop()
                if len(window_rows) >= 2048 or len(window_flow_rows) >= 8192:
                    flush_windows()
            # Release a bounded origin's temporary sets and flow-ID arrays.
            del window_data
            del flows_by_origin[origin_ip]
        flush_windows()
        window_preview=[item[1] for item in window_preview_entries]
        # Packet-based directionality: no reliance on an inferred TCP origin.
        # "nonconfigured" is not asserted to mean Internet.
        egress: dict[str, Counter] = defaultdict(Counter)
        if nets:
            for p in db.execute('SELECT src_ip,dst_ip,ip_declared_bytes,l4_captured_payload_bytes FROM packets '
                                'WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL'):
                src, dest = p['src_ip'], p['dst_ip']
                if any(ip_address(src) in net for net in nets) and not any(ip_address(dest) in net for net in nets):
                    egress[src]['ip_declared_bytes'] += p['ip_declared_bytes'] or 0
                    egress[src]['l4_observed_bytes'] += p['l4_captured_payload_bytes'] or 0
                    egress[src]['packet_count'] += 1

        host_preview=[]
        for ip,h in sorted(hosts.items()):
            is_local = bool(nets and any(ip_address(ip) in net for net in nets))
            outbound = dict(status=('available_configured_cidrs' if is_local else
                                    'not_configured_local' if nets else 'requires_local_cidrs'),
                            to_nonconfigured_ip_declared_bytes=(egress[ip]['ip_declared_bytes'] if is_local else None),
                            to_nonconfigured_l4_observed_bytes=(egress[ip]['l4_observed_bytes'] if is_local else None),
                            to_nonconfigured_packet_count=(egress[ip]['packet_count'] if is_local else None))
            metrics = dict(origin_ip=ip, flow_count=h['flow_count'],
                           first_seen_ns=h['first_seen_ns'], last_seen_ns=h['last_seen_ns'],
                           unique_responder_ip_count=len(h['unique_destination_ips']),
                           unique_protocol_port_count=len(h['unique_destination_ports']),
                           protocol_flow_counts=_counts(h['protocol_counts']),
                           observed_tcp_state_flow_counts=_counts(h['tcp_states']),
                           orig_packet_count=h['packets_orig'], resp_packet_count=h['packets_resp'],
                           orig_ip_declared_bytes=h['orig_declared_ip_bytes'],
                           resp_ip_declared_bytes=h['resp_declared_ip_bytes'],
                           orig_l4_observed_bytes=h['orig_observed_l4_bytes'],
                           resp_l4_observed_bytes=h['resp_observed_l4_bytes'],
                           orientation_not_syn_confirmed_count=h['origin_inferred_count'],
                           visibility_flag_occurrences=_counts(h['visibility_flags']),
                           outbound_to_nonconfigured=outbound,
                           scope='observed_origin_address_not_physical_host')
            db.execute('INSERT INTO feature_hosts VALUES(?,?)', (ip,_json(metrics)))
            if len(host_preview)<max_json_hosts:
                host_preview.append(metrics)

        dns_clients: dict[str, dict] = {}
        for record in db.execute("SELECT data_json FROM events WHERE event_kind='dns' ORDER BY packet_frame,event_id"):
            e = json.loads(record[0])
            if e['query_packet_ref'] is None:
                continue
            ip = e['client_ip']
            if ip not in dns_clients:
                dns_clients[ip] = dict(query_count=0, unique_qnames=set(), nxdomain_qnames=set(),
                                       matched_query_count=0, unanswered_count=0,
                                       ambiguous_count=0, first_query_ns=None,
                                       last_query_ns=None)
            d=dns_clients[ip]
            d['query_count']+=1
            if e['qname_normalized']:
                d['unique_qnames'].add(e['qname_normalized'])
            if e['match_status']=='matched':
                d['matched_query_count']+=1
                if e['rcode']==3 and e['qname_normalized']:
                    d['nxdomain_qnames'].add(e['qname_normalized'])
            if e['match_status']=='unanswered': d['unanswered_count']+=1
            if e['match_status']=='ambiguous': d['ambiguous_count']+=1
            ts=e['query_ts_ns']
            d['first_query_ns']=ts if d['first_query_ns'] is None else min(d['first_query_ns'],ts)
            d['last_query_ns']=ts if d['last_query_ns'] is None else max(d['last_query_ns'],ts)
        dns_preview=[]
        for ip,d in sorted(dns_clients.items()):
            row=dict(client_ip=ip, query_count=d['query_count'],
                     unique_qname_count=len(d['unique_qnames']),
                     matched_query_count=d['matched_query_count'],
                     unique_matched_nxdomain_qname_count=len(d['nxdomain_qnames']),
                     unmatched_query_count=d['unanswered_count'],
                     ambiguous_query_count=d['ambiguous_count'],
                     first_query_ns=d['first_query_ns'], last_query_ns=d['last_query_ns'],
                     registered_domain_grouping='not_implemented_psl_required',
                     caveat='unmatched_queries_are_not_nxdomain')
            db.execute('INSERT INTO feature_dns_clients VALUES(?,?)',(ip,_json(row)))
            if len(dns_preview)<max_json_hosts: dns_preview.append(row)

        arp_bindings: dict[str,dict] = {}
        for record in db.execute("SELECT data_json FROM events WHERE event_kind='arp' ORDER BY packet_frame,event_id"):
            e = json.loads(record[0]); ip=e.get('sender_ip'); mac=e.get('sender_mac')
            if not ip or not mac or ip == '0.0.0.0': continue
            if ip not in arp_bindings:
                arp_bindings[ip] = dict(mac_to_frames=defaultdict(list), observation_count=0)
            a=arp_bindings[ip]
            a['observation_count']+=1
            if len(a['mac_to_frames'][mac])<12: a['mac_to_frames'][mac].append(e['packet_ref'])
        arp_preview=[]
        for ip,a in sorted(arp_bindings.items()):
            row=dict(ip=ip, observed_distinct_sender_mac_count=len(a['mac_to_frames']),
                     observation_count=a['observation_count'],
                     sender_mac_frame_samples={m:a['mac_to_frames'][m] for m in sorted(a['mac_to_frames'])},
                     contradictory_bindings_observed=len(a['mac_to_frames'])>1,
                     caveat='mac_change_not_proof_of_spoofing')
            db.execute('INSERT INTO feature_arp_bindings VALUES(?,?)',(ip,_json(row)))
            if len(arp_preview)<max_json_hosts: arp_preview.append(row)

        icmp_hosts: dict[str,dict] = defaultdict(lambda:dict(v4=set(),v6=set(),echo_request_count=0))
        for record in db.execute("SELECT data_json FROM events WHERE event_kind='icmp' ORDER BY packet_frame,event_id"):
            e=json.loads(record[0])
            if (e['ip_version']==4 and e['type']==8) or (e['ip_version']==6 and e['type']==128):
                ip = e['src_ip']; dest = e['dst_ip']
                if not ip or not dest: continue
                d=icmp_hosts[ip];d['echo_request_count']+=1
                d['v6' if e['ip_version']==6 else 'v4'].add(dest)
        icmp_preview=[]
        for ip,d in sorted(icmp_hosts.items()):
            row=dict(source_ip=ip, echo_request_count=d['echo_request_count'],
                     ipv4_unique_echo_target_count=len(d['v4']),
                     ipv6_unique_echo_target_count=len(d['v6']))
            db.execute('INSERT INTO feature_icmp_hosts VALUES(?,?)',(ip,_json(row)))
            if len(icmp_preview)<max_json_hosts: icmp_preview.append(row)

        summary=dict(communication_group_count=len(groups),
                     grouped_flow_count=total_group_flows,
                     timing_groups_with_insufficient_starts=insufficient_groups,
                     window_row_counts=_counts(window_counts),
                     host_profile_count=len(hosts),
                     dns_client_profile_count=len(dns_clients),
                     arp_sender_binding_ip_count=len(arp_bindings),
                     arp_multiple_mac_observation_ip_count=sum(len(a['mac_to_frames'])>1 for a in arp_bindings.values()),
                     icmp_echo_source_count=len(icmp_hosts),
                     windows_sec=list(windows_sec),
                     local_cidr_count=len(nets),
                     capture_span_ns=(global_last-anchor if anchor is not None else None),
                     quality_warnings=[w['code'] for w in capture.get('parse_warnings',[])])
        # Secondary indexes are equivalent when created after bulk loading;
        # creating them upfront makes every single high-cardinality insert
        # maintain three B-trees unnecessarily.
        db.execute('CREATE INDEX IF NOT EXISTS feature_group_flows_by_flow ON feature_group_flows(flow_id)')
        db.execute('CREATE INDEX IF NOT EXISTS feature_windows_by_kind ON feature_windows(kind)')
        db.execute('CREATE INDEX IF NOT EXISTS feature_window_flows_by_flow ON feature_window_flows(flow_id)')
        db.commit()
        return dict(version=FEATURE_VERSION, measurement_scope='capture_only',
                    reference_parity='not_claimed',
                    orientation_note='UDP first-packet orientation is provisional, not a missing TCP handshake',
                    feature_status='observations_only_no_alerts',
                    parameters=parameters, summary=summary,
                    communication_groups=group_preview,
                    communication_groups_preview_truncated=len(groups)>max_json_groups,
                    window_observations=window_preview,
                    window_observations_preview_truncated=sum(window_counts.values())>max_json_windows,
                    host_observations=host_preview,
                    host_observations_preview_truncated=len(hosts)>max_json_hosts,
                    dns_client_observations=dns_preview,
                    dns_client_observations_preview_truncated=len(dns_clients)>max_json_hosts,
                    arp_binding_observations=arp_preview,
                    arp_binding_observations_preview_truncated=len(arp_bindings)>max_json_hosts,
                    icmp_echo_observations=icmp_preview,
                    icmp_echo_observations_preview_truncated=len(icmp_hosts)>max_json_hosts,
                    complete_observations_in='SQLite feature_* tables',
                    provenance='feature_group_flows / feature_window_flows -> flow_packets -> packets')
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
