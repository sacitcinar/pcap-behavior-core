"""Read-only, bounded dashboard selection from the transient forensic index.

Rows are *observations*, never new security findings. All flows and DNS events
are scanned for aggregates; top-N selection affects presentation only.
"""
from __future__ import annotations
from collections import Counter, defaultdict
import heapq
import ipaddress
import json
from datetime import datetime, timezone

TABLE_LIMIT = 1000


def _ip_sort(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
        return f'{addr.version}:{int(addr):039d}'
    except (ValueError, TypeError):
        return '9:' + str(value)


def _num(value):
    return int(value or 0)


def _rank_balanced(rows, metrics, limit=TABLE_LIMIT, key='id'):
    """Keep rows strong in ANY observed metric; no threat/risk scoring."""
    if len(rows) <= limit:
        return sorted(rows, key=lambda r: (-r.get(metrics[0], 0), str(r[key])))
    by_id = {}
    # Top candidates for several independent traffic dimensions.
    quota = max(1, limit // (2 * len(metrics)))
    sorts = [sorted(rows, key=lambda r: (-r.get(metric, 0), str(r[key]))) for metric in metrics]
    for group in sorts:
        for row in group[:quota]:
            by_id[row[key]] = row
    # Balanced round-robin fills remaining slots without silently ignoring
    # low-byte / high-frequency or high-peer-count observations.
    for i in range(len(rows)):
        if len(by_id) >= limit:
            break
        for group in sorts:
            if len(by_id) >= limit:
                break
            row = group[i]
            by_id[row[key]] = row
    return sorted(by_id.values(), key=lambda r: (-r.get(metrics[0], 0), str(r[key])))[:limit]


def _push_best(heaps, item, flow):
    for key in heaps:
        h = heaps[key]
        rank = (_num(item[key]), str(item['id']))
        entry = (rank, item)
        if len(h) < TABLE_LIMIT:
            heapq.heappush(h, entry)
        elif rank > h[0][0]:
            heapq.heapreplace(h, entry)


def _flow_selection(heaps, limit):
    groups = [sorted(v, key=lambda pair: pair[0], reverse=True) for v in heaps.values()]
    selected = {}
    for i in range(TABLE_LIMIT):
        for group in groups:
            if len(selected) >= limit:
                break
            if i < len(group):
                item = group[i][1]
                selected[item['id']] = item
        if len(selected) >= limit:
            break
    return sorted(selected.values(), key=lambda r: (-r['packets'], r['id']))


def collect_dashboard(db, capture: dict, *, limit: int = TABLE_LIMIT) -> dict:
    """Observe all data, return up to limit rows per traffic table.

    Local/external roles are intentionally *not* inferred. Origin/responder
    follow the flow reconstruction and can be uncertain in incomplete captures.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > TABLE_LIMIT:
        raise ValueError('Traffic table limit must be an integer from 1 to 1000')
    hosts = {}
    peers = {}
    candidate_heaps = {key: [] for key in ('packets', 'bytes', 'duration', 'payload')}
    flow_count = 0

    def host_for(ip):
        if ip not in hosts:
            hosts[ip] = dict(id=ip, ip=ip, sent=0, received=0, packets=0,
                             flows=0, peers=set(), protocols=set())
        return hosts[ip]

    for (raw,) in db.execute('SELECT data_json FROM flows'):
        f = json.loads(raw)
        flow_count += 1
        # Small legacy episode fixtures contain only destination IP, not full flow data.
        # These are not valid traffic records for host/connection tables.
        if not f.get('origin_ip') or not f.get('responder_ip'):
            continue
        origin, responder = f['origin_ip'], f['responder_ip']
        prot = f['protocol']
        sent = _num(f.get('orig_l4_payload_observed_bytes'))
        received = _num(f.get('resp_l4_payload_observed_bytes'))
        captured_sent = _num(f.get('orig_ip_captured_bytes'))
        captured_received = _num(f.get('resp_ip_captured_bytes'))
        orig_pkts = _num(f.get('orig_packet_count'))
        resp_pkts = _num(f.get('resp_packet_count'))
        packet_total = orig_pkts + resp_pkts
        duration = _num(f.get('observed_duration_ns'))
        for ip, peer, out, inc in ((origin, responder, sent, received),
                                   (responder, origin, received, sent)):
            host = host_for(ip)
            host['sent'] += out
            host['received'] += inc
            host['packets'] += packet_total
            host['flows'] += 1
            host['peers'].add(peer)
            host['protocols'].add(prot)
        k = (origin, responder, prot, f.get('responder_port'))
        if k not in peers:
            peers[k] = dict(id='|'.join(map(str, k)), origin=origin, responder=responder,
                            protocol=prot, port=f.get('responder_port'),
                            flows=0, packets=0, sent=0, received=0,
                            first=None, last=None)
        a = peers[k]
        a['flows'] += 1
        a['packets'] += packet_total
        a['sent'] += sent
        a['received'] += received
        fst, lst = f.get('first_seen_ns'), f.get('last_seen_ns')
        if fst is not None:
            a['first'] = fst if a['first'] is None else min(a['first'], fst)
        if lst is not None:
            a['last'] = lst if a['last'] is None else max(a['last'], lst)
        item = dict(id=f['flow_id'], origin=origin, responder=responder,
                    origin_port=f.get('origin_port'), port=f.get('responder_port'),
                    protocol=prot, packets=packet_total, bytes=captured_sent+captured_received,
                    payload=sent+received, sent=sent, received=received,
                    duration=duration, first=fst, last=lst,
                    state=f.get('observed_tcp_state') or '—')
        _push_best(candidate_heaps, item, f)

    host_rows = []
    for h in hosts.values():
        host_rows.append(dict(id=h['id'], ip=h['ip'], sent=h['sent'], received=h['received'],
                              packets=h['packets'], flows=h['flows'],
                              peer_count=len(h['peers']), data=h['sent'] + h['received']))
    peer_rows = list(peers.values())
    for row in peer_rows:
        row['data'] = row['sent'] + row['received']

    dns_by_name = {}
    dns_total = 0
    event_rows = (db.execute("SELECT data_json FROM events WHERE event_kind = 'dns'")
                  if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
                  else ())
    for (raw,) in event_rows:
        event = json.loads(raw)
        if event.get('query_packet_ref') is None:
            continue   # Orphan responses are not client queries.
        dns_total += 1
        name = event.get('qname_normalized') or '(unknown)'
        if name not in dns_by_name:
            dns_by_name[name] = dict(id=name, name=name, queries=0, nxdomain=0,
                                     unanswered=0, clients=set(), first=None)
        v = dns_by_name[name]
        v['queries'] += 1
        if event.get('match_status') == 'matched' and event.get('rcode') == 3:
            v['nxdomain'] += 1
        if event.get('match_status') == 'unanswered':
            v['unanswered'] += 1
        if event.get('client_ip'):
            v['clients'].add(event['client_ip'])
        ts = event.get('query_ts_ns')
        if ts is not None:
            v['first'] = ts if v['first'] is None else min(v['first'], ts)
    dns_rows = []
    for v in dns_by_name.values():
        dns_rows.append(dict(id=v['id'], name=v['name'], queries=v['queries'],
                             nxdomain=v['nxdomain'], unanswered=v['unanswered'],
                             clients=len(v['clients']), first=v['first']))

    first, last = capture.get('first_ts_ns'), capture.get('last_ts_ns')
    timeline = []
    if first is not None and last is not None and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='packets'").fetchone():
        # At most 48 bins, but every packet contributes to exactly one.
        width = max(1, ((last - first) // 48) + 1)
        counts = dict(db.execute('SELECT CAST((ts_ns - ?) / ? AS INTEGER) AS bucket, COUNT(*) '
                                 'FROM packets GROUP BY bucket ORDER BY bucket', (first, width)).fetchall())
        for i in range(48):
            ts = first + i * width
            if ts > last:
                break
            timeline.append({'start': ts, 'end': min(last, ts + width - 1),
                             'packets': int(counts.get(i, 0))})
    return dict(hosts=_rank_balanced(host_rows, ['data','packets','flows','peer_count'],limit),
                host_total=len(host_rows),
                peers=_rank_balanced(peer_rows, ['data','packets','flows'],limit),
                peer_total=len(peer_rows),
                connections=_flow_selection(candidate_heaps,limit),
                connection_total=flow_count,
                dns=_rank_balanced(dns_rows, ['queries','nxdomain','unanswered','clients'],limit),
                dns_total=len(dns_rows), dns_query_total=dns_total,
                timeline=timeline, timeline_packets=sum(x['packets'] for x in timeline))
