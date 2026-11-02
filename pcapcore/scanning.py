"""Capture-local TCP horizontal and vertical scan-pattern observations.

Uses *observed* TCP SYN attempts with two explicit evidence modes:
  - Existing SYN-only or RST-refused attempts, or
  - Short, fully observed, payload-free completed handshakes to at least 32
    near-adjacent IPv4 destinations in a 300-second window. This mode is
    evidence of dense connect probing, not proof of an attack.

Confirmed preceding DNS A answers for the same originating host can resolve
an otherwise ambiguous cross-host SYN-only episode into a name-backed
connection fanout when at least 80% of target IPs and six independent DNS
names are represented. Unexplained attempts are still tested separately.
This is evidence disambiguation, not a benign traffic label or IOC rule.

Sliding 300s windows prevent fixed-window boundary misses. Dense explicit
RST refusals across at least 64 different ports can retain a rotated sweep
within a bounded oversized-group exception; repeated six-port cycles remain
excluded. Overlapping positive
windows are one episode; cross-axis episodes are correlated only if they share
actual observed attempt flows. No labels, IOCs, threat attribution, or numeric
risk scores enter detection. All flow -> frame provenance is persisted.

This detector uses TCP packet and flow evidence only. UDP scanning is not
inferred from this detector's results.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from bisect import bisect_right
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sqlite3
from typing import Any

from .beaconing import _schema, _first_frames
from .flows import _id
from .features import _json, NS

DETECTOR_ID = 'tcp_port_scan_patterns'
DETECTOR_VERSION = '0.24.0'
ELIGIBLE_TCP_STATES = frozenset({'syn_only', 'refused_rst'})
BAD_VISIBILITY = frozenset({'time_anomaly', 'truncated_or_partial', 'fragmented'})
# Conservative evidence extension: completed, payload-free handshakes to a dense
# contiguous address set are observable connect-probing, not necessarily attacks.
CONNECT_SWEEP_MIN_HOSTS = 32
CONNECT_SWEEP_MIN_ADJACENT_EDGE_FRACTION = 0.80
CONNECT_SWEEP_MAX_DURATION_NS = 10 * NS

# A burst of SYN-only attempts across many unrelated destinations is ambiguous
# when the same host recently resolved most destination addresses through
# several distinct names. This is NOT a malware/benign classification.
DNS_FANOUT_MAX_LOOKBACK_NS = 300 * NS
DNS_FANOUT_MIN_TARGET_COVERAGE = 0.80
DNS_FANOUT_MIN_DISTINCT_NAMES = 6

# High-confidence explicit refusal evidence can overcome broad retry rotation.
# Deliberately conservative: 64 distinct RST-refused ports within one 300s
# window. This is packet geometry, not a malware label or attack conclusion.
DENSE_REFUSED_PORTS_MIN = 64
# Retain a bounded resource ceiling even in the exceptional high-density path.
MAX_DENSE_GROUP_MULTIPLIER = 10


@dataclass(frozen=True)
class ScanParameters:
    min_distinct_destination_ports: int = 6
    min_distinct_destination_ips: int = 6
    sliding_window_seconds: int = 300
    max_group_flows: int = 50000
    min_distinct_probe_fraction: float = 0.5  # reject broadly retry-dominated patterns

    def __post_init__(self):
        if not 0 < self.min_distinct_probe_fraction <= 1:
            raise ValueError('min_distinct_probe_fraction must be >0 and <=1')
        for name in ('min_distinct_destination_ports', 'min_distinct_destination_ips'):
            value = getattr(self, name)
            if type(value) is not int or value < 2:
                raise ValueError(f'{name} must be an integer >= 2')
        if type(self.sliding_window_seconds) is not int or self.sliding_window_seconds <= 0:
            raise ValueError('sliding_window_seconds must be a positive integer')
        if type(self.max_group_flows) is not int or self.max_group_flows < max(
                self.min_distinct_destination_ports, self.min_distinct_destination_ips):
            raise ValueError('max_group_flows must exceed all distinct thresholds')


def _axis_key(axis: str, flow: dict) -> tuple:
    if axis == 'vertical':
        return (flow['origin_ip'], flow['responder_ip'], flow['protocol'])
    return (flow['origin_ip'], flow['responder_port'], flow['protocol'])


def _dim_value(axis: str, flow: dict) -> str | int:
    return flow['responder_port'] if axis == 'vertical' else flow['responder_ip']


def _subject(axis: str, key: tuple) -> dict:
    if axis == 'vertical':
        return {'scan_axis':axis, 'origin_ip':key[0], 'responder_ip':key[1], 'protocol':key[2]}
    return {'scan_axis':axis, 'origin_ip':key[0], 'responder_port':key[1], 'protocol':key[2]}


def _eligible(flow: dict) -> bool:
    return (flow['protocol'] == 'tcp'
            and flow['origin_basis'] == 'syn_observed'
            and flow['observed_tcp_state'] in ELIGIBLE_TCP_STATES
            and not (set(flow['flow_visibility_flags']) & BAD_VISIBILITY))



def _has_dense_explicit_port_refusals(flows: list[dict], window_ns: int,
                                      minimum: int = DENSE_REFUSED_PORTS_MIN) -> bool:
    """Observe many *different* RST-refused destination ports in one window.

    Source TCP resets, incomplete handshakes and repeated probes to just a
    handful of targets do not establish this signal. O(n log n) sorting,
    bounded live per-port counter, early stop when confirmed.
    """
    refused = sorted(
        (f['first_seen_ns'], f['responder_port'])
        for f in flows
        if f['observed_tcp_state'] == 'refused_rst' and _eligible(f)
    )
    if len(refused) < minimum:
        return False
    active: Counter[int] = Counter()
    left = 0
    for ts, port in refused:
        active[port] += 1
        while ts - refused[left][0] > window_ns:
            gone = refused[left][1]
            active[gone] -= 1
            if not active[gone]:
                del active[gone]
            left += 1
        if len(active) >= minimum:
            return True
    return False


def _completed_connect_sweep_flow_ids(flows: list[dict], window_ns: int) -> set[str]:
    """Conservatively qualify short, empty, completed TCP connect sweeps.

    All captured handshakes are complete, carry no observed application bytes,
    and have a FIN. At least 32 distinct IPv4 targets within a sliding window
    must form a dense address-neighbor set (>=80% of possible adjacent edges).
    This is a *target geometry observation*, not attack or intent proof.
    Scattered normal connection bursts and payload-bearing sessions are out.
    """
    from ipaddress import IPv4Address, AddressValueError

    candidates = []
    for f in flows:
        if not (f['protocol'] == 'tcp' and f['origin_basis'] == 'syn_observed'
                and f['observed_tcp_state'] == 'observed_handshake'
                and not (set(f['flow_visibility_flags']) & BAD_VISIBILITY)
                and f['orig_l4_payload_observed_bytes'] == 0
                and f['resp_l4_payload_observed_bytes'] == 0
                and f['observed_duration_ns'] <= CONNECT_SWEEP_MAX_DURATION_NS
                and 'FIN' in f['tcp_state_flags']):
            continue
        try:
            addr = int(IPv4Address(f['responder_ip']))
        except (AddressValueError, ValueError):
            continue
        candidates.append((f['first_seen_ns'], f['flow_id'], addr))
    if len(candidates) < CONNECT_SWEEP_MIN_HOSTS:
        return set()
    candidates.sort()
    active: Counter[int] = Counter()
    edges = 0
    left = 0
    intervals: list[list[int]] = []
    for right, (ts, _, addr) in enumerate(candidates):
        if active[addr] == 0:
            edges += (active[addr - 1] > 0) + (active[addr + 1] > 0)
        active[addr] += 1
        while ts - candidates[left][0] > window_ns:
            gone = candidates[left][2]
            active[gone] -= 1
            if active[gone] == 0:
                del active[gone]
                edges -= (active[gone - 1] > 0) + (active[gone + 1] > 0)
            left += 1
        if (len(active) >= CONNECT_SWEEP_MIN_HOSTS and
                edges >= CONNECT_SWEEP_MIN_ADJACENT_EDGE_FRACTION * (len(active) - 1)):
            if intervals and left <= intervals[-1][1]:
                intervals[-1][1] = right
            else:
                intervals.append([left, right])
    return {candidates[i][1] for lo, hi in intervals for i in range(lo, hi + 1)}



def _positive_dns_answer_index(db: sqlite3.Connection) -> dict[tuple[str, str], list[tuple[int, str]]]:
    """Use only confirmed in-capture A query/response pairs, scoped to client.

    No reverse DNS, IOC/hostname reputation, or external resolution. Events
    are already normalized and stored by the packet reader; no PCAP reparse.
    """
    from ipaddress import IPv4Address, AddressValueError

    index: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)
    for (blob,) in db.execute("SELECT data_json FROM events WHERE event_kind='dns'"):
        event = json.loads(blob)
        if not (event.get('match_status') == 'matched' and event.get('rcode') == 0
                and event.get('qtype') == 1
                and isinstance(event.get('response_ts_ns'), int)
                and event.get('response_packet_ref') is not None
                and event.get('query_packet_ref') is not None):
            continue
        client = event.get('client_ip')
        name = event.get('qname_normalized')
        if not (isinstance(client, str) and isinstance(name, str) and name):
            continue
        for ip in event.get('answer_ip_addresses', []):
            try:
                IPv4Address(ip)
            except (ValueError, AddressValueError, TypeError):
                continue
            index[(client, ip)].append((event['response_ts_ns'], name))
    for entries in index.values():
        entries.sort()
    return index


def _dns_resolution_context(episode: dict, flow_lookup: dict[str, dict],
                            answer_index: dict[tuple[str, str], list[tuple[int, str]]],
                            lookback_ns: int = DNS_FANOUT_MAX_LOOKBACK_NS) -> dict:
    """A non-maliciousness-neutral observation of prior name resolution.

    A matching answer means this host has a plausible application reason to
    connect to an IP; it does NOT prove an attempted connection is harmless.
    """
    targets = set()
    resolved = set()
    names = set()
    covered_flows = set()
    states = Counter()
    for fid in episode['flow_ids']:
        flow = flow_lookup[fid]
        states[flow['observed_tcp_state']] += 1
        target = flow['responder_ip']
        targets.add(target)
        answers = answer_index.get((flow['origin_ip'], target), [])
        if not answers:
            continue
        # Last successful answer observed at or before the SYN frame.
        pos = bisect_right(answers, (flow['first_seen_ns'], chr(0x10ffff))) - 1
        if pos >= 0 and 0 <= flow['first_seen_ns'] - answers[pos][0] <= lookback_ns:
            resolved.add(target)
            names.add(answers[pos][1])
            covered_flows.add(fid)
    return {'target_count':len(targets), 'matched_target_count':len(resolved),
            'distinct_name_count':len(names), 'matched_flow_ids':covered_flows,
            'only_unanswered_syn':states['syn_only'] == len(episode['flow_ids']),
            'matched_target_fraction':len(resolved) / len(targets) if targets else 0.0}


def _dns_backed_unestablished_fanout(episode: dict, flow_lookup: dict[str, dict],
                                     answers: dict[tuple[str, str], list[tuple[int, str]]]) -> tuple[bool, dict]:
    """Distinguish DNS-driven failed connection fanout from target probing.

    Only narrowly qualified, unanswered SYN-only horizontal episodes are
    withheld; completed connection sweeps, explicit RST refusals, mixed
    evidence, sparse DNS, and vertical port sweeps remain eligible.
    """
    ctx = _dns_resolution_context(episode, flow_lookup, answers)
    matched = (ctx['only_unanswered_syn']
               and ctx['target_count'] >= DNS_FANOUT_MIN_DISTINCT_NAMES
               and ctx['distinct_name_count'] >= DNS_FANOUT_MIN_DISTINCT_NAMES
               and ctx['matched_target_fraction'] >= DNS_FANOUT_MIN_TARGET_COVERAGE)
    return matched, ctx

def _ordered_adjacent_target_sweep(episode: dict, flow_lookup: dict[str, dict]) -> bool:
    """Preserve direct SYN evidence of a dense *ordered* IPv4 address sweep.

    A scanner may resolve hostnames before probing them. DNS alone must not
    discard 32+ near-consecutive IP targets visited in address order. This
    stronger constraint than mere adjacency prevents an unordered multi-IP
    application/CDN fanout from becoming a sweep on address geometry alone.
    """
    from ipaddress import IPv4Address, AddressValueError

    ordered = sorted((flow_lookup[fid] for fid in episode['flow_ids']),
                     key=lambda f: (f['first_seen_ns'], f['flow_id']))
    seen: set[int] = set()
    addresses: list[int] = []
    for f in ordered:
        try:
            addr = int(IPv4Address(f['responder_ip']))
        except (ValueError, AddressValueError):
            return False
        if addr not in seen:
            seen.add(addr)
            addresses.append(addr)
    if len(addresses) < CONNECT_SWEEP_MIN_HOSTS:
        return False
    adjacent_steps = sum(abs(b - a) == 1 for a, b in zip(addresses, addresses[1:]))
    return (adjacent_steps >= CONNECT_SWEEP_MIN_ADJACENT_EDGE_FRACTION *
            (len(addresses) - 1))


def _positive_episodes(members: list[dict], axis: str, min_unique: int,
                       window_ns: int) -> list[dict]:
    """O(n) sliding distinct-count analysis, merging overlapping positive spans.

    No partitioning by capture-anchored feature windows: events near a boundary
    must be eligible to form one continuous positive window.
    """
    members = sorted(members, key=lambda x: (x['first_seen_ns'], x['flow_id']))
    counts: Counter = Counter()
    left = 0
    episodes: list[dict] = []
    first_trigger = None
    for right, flow in enumerate(members):
        counts[_dim_value(axis, flow)] += 1
        while flow['first_seen_ns'] - members[left]['first_seen_ns'] > window_ns:
            item = _dim_value(axis, members[left]); counts[item] -= 1
            if counts[item] == 0: del counts[item]
            left += 1
        if len(counts) < min_unique:
            continue
        if episodes and left <= episodes[-1]['end_index']:
            episodes[-1]['end_index'] = right
            episodes[-1]['max_distinct_in_window'] = max(
                episodes[-1]['max_distinct_in_window'], len(counts))
        else:
            first_trigger = (members[left]['first_seen_ns'], flow['first_seen_ns'])
            episodes.append({'start_index':left, 'end_index':right,
                             'max_distinct_in_window':len(counts),
                             'trigger_window_first_ns':first_trigger[0],
                             'trigger_window_last_ns':first_trigger[1]})
    result=[]
    for e in episodes:
        selected = members[e['start_index']:e['end_index'] + 1]
        dims = {_dim_value(axis,f) for f in selected}
        states = Counter(f['observed_tcp_state'] for f in selected)
        dimension_counts = Counter(_dim_value(axis, f) for f in selected)
        singleton_dimensions = sum(n == 1 for n in dimension_counts.values())
        # An unrelated retry storm to ONE destination must not erase a real
        # multi-destination sweep. Conversely, a round-robin pattern that
        # repeatedly revisits MOST destinations stays retry-dominated.
        singleton_fraction = singleton_dimensions / len(dims)
        overall_fraction = len(dims) / len(selected)
        result.append({
            **({'completed_empty_handshake_count': states['observed_handshake']}
               if states['observed_handshake'] else {}),
            'flow_ids': [f['flow_id'] for f in selected],
            'first_seen_ns': selected[0]['first_seen_ns'],
            'last_seen_ns': selected[-1]['first_seen_ns'],
            'unique_dimensions': len(dims),
            'distinct_probe_fraction': round(overall_fraction, 6),
            'single_probe_dimension_count': singleton_dimensions,
            'single_probe_dimension_fraction': round(singleton_fraction, 6),
            'unique_values_sample': sorted(dims, key=lambda x:str(x))[:20],
            'unique_values_preview_truncated': len(dims) > 20,
            'attempt_flow_count':len(selected),
            'syn_only_attempt_count':states['syn_only'],
            'explicit_rst_refusal_count':states['refused_rst'],
            'max_distinct_in_window':e['max_distinct_in_window'],
            'trigger_window_first_ns':e['trigger_window_first_ns'],
            'trigger_window_last_ns':e['trigger_window_last_ns']})
    return result


def _components(candidates: list[dict]) -> list[list[dict]]:
    """Correlate axes only with *shared* attempts, not host/time resemblance."""
    parent = list(range(len(candidates)))

    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a,b):
        ra, rb = root(a), root(b)
        if ra != rb:
            parent[max(ra,rb)] = min(ra,rb)

    owners: dict[str,int] = {}
    for i,c in enumerate(candidates):
        for fid in c['flow_ids']:
            if fid in owners: union(owners[fid], i)
            else: owners[fid]=i
    grouped: dict[int,list[dict]] = defaultdict(list)
    for i,c in enumerate(candidates): grouped[root(i)].append(c)
    return list(grouped.values())


def analyze_scan_patterns(index_path: str | Path, capture: dict, *,
                          parameters: ScanParameters | None = None,
                          max_json_findings: int = 25,
                          max_json_evaluations: int = 25) -> dict:
    cfg = parameters or ScanParameters()
    if max_json_findings < 0 or max_json_evaluations < 0:
        raise ValueError('JSON limits must be nonnegative')
    db = sqlite3.connect(str(index_path))
    db.row_factory = sqlite3.Row
    try:
        row = db.execute('SELECT capture_id FROM feature_run LIMIT 1').fetchone()
        if row is None or row['capture_id'] != capture['capture_id']:
            raise ValueError('Missing/mismatched feature store')
        _schema(db)  # Reuse the shared detector storage schema.
        if db.execute('SELECT 1 FROM detector_runs WHERE detector_id=?',
                      (DETECTOR_ID,)).fetchone():
            raise FileExistsError('TCP scanning detector already run; create a fresh index')
        db.execute('INSERT INTO detector_runs VALUES (?,?,?,?)',
                   (DETECTOR_ID, DETECTOR_VERSION, capture['capture_id'], _json(asdict(cfg))))
        data = [json.loads(row[0]) for row in db.execute('SELECT data_json FROM flows')]
        flow_lookup = {f['flow_id']: f for f in data}
        dns_answers = _positive_dns_answer_index(db)
        # Reuse normalized flows; do not reparse PCAP or recompute
        # packet/byte metrics. The scan-specific sliding geometry is new.
        groups: dict[tuple,list[dict]] = defaultdict(list)
        for f in data:
            if f['protocol'] not in ('tcp','udp'):
                continue
            for axis in ('vertical','horizontal'):
                groups[(axis, _axis_key(axis,f))].append(f)
        evaluation_preview=[]
        candidates=[]
        evaluations=Counter()
        for (axis,key),flows in sorted(groups.items(),key=lambda kv:(kv[0][0],str(kv[0][1]))):
            subject = _subject(axis,key)
            gid=_id('SG-',capture['capture_id'],axis,key)
            eval_id=_id('DE-',capture['capture_id'],DETECTOR_ID,gid)
            reason=[]
            states = Counter(f['observed_tcp_state'] or 'not_tcp' for f in flows)
            basic_eligible = [f for f in flows if _eligible(f)]
            window_ns = cfg.sliding_window_seconds * NS
            # A hard cap still protects very large groups; within the bounded
            # exception, a group above the soft cap is processed only if the
            # *raw flow states* show a dense, explicitly refused multiport sweep.
            # There is no IP/port/label allowlist.
            high_density_overflow = (
                axis == 'vertical' and key[-1] == 'tcp'
                and cfg.max_group_flows < len(flows) <=
                    cfg.max_group_flows * MAX_DENSE_GROUP_MULTIPLIER
                and _has_dense_explicit_port_refusals(basic_eligible, window_ns))
            # The existing unestablished-SYN detector remains untouched unless
            # independent dense, payload-free completed connections qualify.
            connect_ids = (_completed_connect_sweep_flow_ids(
                flows, cfg.sliding_window_seconds * NS)
                if axis == 'horizontal' and key[-1] == 'tcp'
                   and len(flows) <= cfg.max_group_flows else set())
            eligible = basic_eligible + [f for f in flows if f['flow_id'] in connect_ids]
            all_dims = {_dim_value(axis, f) for f in flows}
            eligible_dims = {_dim_value(axis,f) for f in eligible}
            min_unique=(cfg.min_distinct_destination_ports if axis == 'vertical'
                        else cfg.min_distinct_destination_ips)
            metrics={
                'axis':axis, 'protocol':key[-1], 'observed_flow_count':len(flows),
                'observed_distinct_count':len(all_dims),
                'eligible_syn_attempt_flow_count':len(basic_eligible),
                **({'eligible_completed_empty_handshake_count': len(connect_ids)}
                   if connect_ids else {}),
                'eligible_distinct_count':len(eligible_dims),
                'tcp_state_counts':dict(sorted(states.items())),
                'excluded_low_quality_count':sum(bool(set(f['flow_visibility_flags']) & BAD_VISIBILITY) for f in flows),
                'excluded_inferred_direction_count':sum(f['origin_basis'] != 'syn_observed' for f in flows),
                'window_seconds':cfg.sliding_window_seconds,
                'minimum_distinct':min_unique,
                **({'oversized_explicit_rst_port_diversity_verified': True}
                   if high_density_overflow else {}),
            }
            if key[-1] != 'tcp':
                status='not_applicable'; reason.append('udp_nonestablished_state_not_reliably_inferable')
            elif len(flows) > cfg.max_group_flows and not high_density_overflow:
                status='insufficient_data'; reason.append('group_exceeds_analysis_limit_no_sampling')
            else:
                episodes=_positive_episodes(eligible,axis,min_unique,cfg.sliding_window_seconds*NS)
                metrics['geometry_positive_episodes']=len(episodes)
                # Decide from the target diversity *distribution*, not only
                # the number of repeated flows. A legitimate sweep can be
                # surrounded by retries to just one of its targets. That
                # should not suppress the other distinct SYN attempts.
                # Broadly repeated rotations across the targets, however,
                # retain the old conservative rejection policy.
                def support_mode(e):
                    if e['distinct_probe_fraction'] >= cfg.min_distinct_probe_fraction:
                        return 'overall_diversity'
                    if e['single_probe_dimension_fraction'] >= cfg.min_distinct_probe_fraction:
                        return 'concentrated_retries'
                    # Broad rotations across six targets stay excluded, but
                    # large, explicit per-port RST refusals are positive
                    # packet-level evidence despite repeat rotations.
                    if (axis == 'vertical'
                            and e['max_distinct_in_window'] >= DENSE_REFUSED_PORTS_MIN
                            and _has_dense_explicit_port_refusals(
                                (flow_lookup[fid] for fid in e['flow_ids']), window_ns)):
                        return 'dense_explicit_rst_rotation'
                    return 'broad_retries'
                for episode in episodes:
                    episode['probe_support_mode'] = support_mode(episode)
                retry_dominated=[e for e in episodes if e['probe_support_mode'] == 'broad_retries']
                episodes=[e for e in episodes if e['probe_support_mode'] != 'broad_retries']
                metrics['retry_dominated_episodes_excluded']=len(retry_dominated)
                # A non-IP-neighbor burst of unanswered SYNs can be initiated
                # by applications opening many independently resolved names.
                # Use directly observed prior DNS A answers as limited
                # disambiguation, never infer that the traffic is benign.
                dns_withheld = []
                dns_qualified = []
                for ep in episodes:
                    if axis != 'horizontal' or not dns_answers:
                        dns_qualified.append(ep)
                        continue
                    is_name_fanout, ctx = _dns_backed_unestablished_fanout(
                        ep, flow_lookup, dns_answers)
                    if not is_name_fanout:
                        dns_qualified.append(ep)
                        continue
                    if _ordered_adjacent_target_sweep(ep, flow_lookup):
                        # The DNS-name context is real, but address-order
                        # evidence is too strong to discard as browsing.
                        dns_qualified.append(ep)
                        metrics['dns_backed_ordered_sweep_episodes_preserved'] = (
                            metrics.get('dns_backed_ordered_sweep_episodes_preserved', 0) + 1)
                        continue
                    # Preserve genuinely distinct, unexplained probing if
                    # at least the normal diversity threshold survives.
                    unexplained = [flow_lookup[fid] for fid in ep['flow_ids']
                                   if fid not in ctx['matched_flow_ids']]
                    residual = _positive_episodes(
                        unexplained, axis, min_unique, cfg.sliding_window_seconds * NS)
                    residual = [e for e in residual if support_mode(e) != 'broad_retries']
                    for e in residual:
                        e['probe_support_mode'] = support_mode(e)
                    dns_qualified.extend(residual)
                    dns_withheld.append({
                        'matched_target_count':ctx['matched_target_count'],
                        'distinct_dns_name_count':ctx['distinct_name_count'],
                        'original_target_count':ctx['target_count'],
                        'residual_scan_episodes':len(residual)})
                episodes = dns_qualified
                if dns_withheld:
                    metrics['dns_backed_syn_fanout_episodes_reviewed'] = len(dns_withheld)
                    metrics['dns_fanout_observation_summary'] = dns_withheld
                metrics['detected_episodes']=len(episodes)
                if episodes:
                    status='detected'; reason.append('syn_attempt_target_diversity_in_sliding_window')
                    for e in episodes:
                        e.update(axis=axis,subject=subject,evaluation_id=eval_id,group_id=gid)
                        candidates.append(e)
                elif dns_withheld:
                    status='not_detected'; reason.append('observed_dns_backed_unanswered_syn_fanout_not_sufficient_for_scan')
                elif retry_dominated:
                    status='not_detected'; reason.append('retry_dominated_not_distinct_sweep')
                elif len(all_dims) >= min_unique and len(eligible_dims) < min_unique and (
                      metrics['excluded_inferred_direction_count'] > 0 or
                      metrics['excluded_low_quality_count'] > 0):
                    status='limited_visibility'; reason.append('potential_diversity_but_unreliable_origin_or_capture')
                elif len(eligible_dims) < min_unique:
                    status='insufficient_data'; reason.append('too_few_distinct_unestablished_tcp_attempt_targets')
                else:
                    status='not_detected'; reason.append('no_diversity_burst_within_sliding_window')
            db.execute('INSERT INTO detector_evaluations VALUES(?,?,?,?,?)',
                       (eval_id,gid,status,_json(reason),_json(metrics)))
            evaluations[status]+=1
            if status != 'detected' and len(evaluation_preview)<max_json_evaluations:
                evaluation_preview.append({'evaluation_id':eval_id,'group_id':gid,
                                           'subject':subject,'status':status,'reasons':reason})
        preview_findings=[]
        preview_evidence=[]
        counters=Counter({'finding_count':0})
        # A candidate is an axis-specific episode. Connected candidates share
        # one *real* flow, forming one finding with supporting geometry.
        for component in sorted(_components(candidates),
                                key=lambda cs:(min(c['first_seen_ns'] for c in cs),
                                               min(c['evaluation_id'] for c in cs))):
            primary=min(component,key=lambda c:(-c['attempt_flow_count'],
                                                -c['max_distinct_in_window'],
                                                c['axis'],c['evaluation_id']))
            all_flow_ids=set(fid for c in component for fid in c['flow_ids'])
            ordered_flow_ids=sorted(all_flow_ids, key=lambda x:(flow_lookup[x]['first_seen_ns'],x))
            first=min(c['first_seen_ns'] for c in component)
            last=max(c['last_seen_ns'] for c in component)
            fid=_id('FI-',capture['capture_id'],DETECTOR_ID,
                    tuple(sorted((c['evaluation_id'],c['first_seen_ns'],c['last_seen_ns']) for c in component)))
            eids=[]
            for c in sorted(component,key=lambda c:(c is not primary,c['axis'],c['evaluation_id'])):
                eid=_id('EV-',fid,'scan_geometry',c['evaluation_id'],c['first_seen_ns'])
                emetric={k:c[k] for k in ('axis','subject','unique_dimensions','distinct_probe_fraction','unique_values_sample',
                    'unique_values_preview_truncated','attempt_flow_count',
                    'single_probe_dimension_count','single_probe_dimension_fraction',
                    'probe_support_mode','syn_only_attempt_count',
                    'explicit_rst_refusal_count','max_distinct_in_window','trigger_window_first_ns',
                    'trigger_window_last_ns')}
                if c.get('completed_empty_handshake_count'):
                    emetric['completed_empty_handshake_count'] = c['completed_empty_handshake_count']
                evidence={'evidence_id':eid,'finding_id':fid,'evaluation_id':c['evaluation_id'],
                          'type':'observed_scan_axis', 'metrics':emetric,
                          'scope':('TCP SYN-only, RST-refused, and strictly qualified empty '
                                   'completed-handshake attempts' if c.get('completed_empty_handshake_count')
                                   else 'TCP SYN-only or matching RST-refused attempts')}
                db.execute('INSERT INTO detector_evidence VALUES(?,?,?,?)',
                           (eid,c['evaluation_id'],'observed_scan_axis',_json(evidence)))
                if len(preview_evidence)<max_json_findings*4: preview_evidence.append(evidence)
                eids.append(eid)
            # One supporting evidence item, not an independent alarm or score.
            # The source attempts are shared with scan geometry and must never
            # be treated as statistically independent evidence.
            outcome_counts=Counter(flow_lookup[x]['observed_tcp_state'] for x in all_flow_ids)
            outcome_eid=_id('EV-',fid,'tcp_attempt_outcomes')
            outcome_ev={
                'evidence_id':outcome_eid,'finding_id':fid,
                'evaluation_id':primary['evaluation_id'],
                'type':'tcp_attempt_outcomes',
                'metrics':{
                    'syn_without_observed_reply_count':outcome_counts['syn_only'],
                    'explicit_rst_refusal_count':outcome_counts['refused_rst'],
                    'total_distinct_flow_attempts':len(all_flow_ids),
                    **({'completed_empty_handshake_count': outcome_counts['observed_handshake']}
                       if outcome_counts['observed_handshake'] else {}),
                    'not_independent_from_scan_geometry':True}}
            db.execute('INSERT INTO detector_evidence VALUES(?,?,?,?)',
                       (outcome_eid,primary['evaluation_id'],outcome_ev['type'],_json(outcome_ev)))
            if len(preview_evidence)<max_json_findings*4: preview_evidence.append(outcome_ev)
            eids.append(outcome_eid)
            candidate_axes=sorted({c['axis'] for c in component})
            finding={
                'finding_id':fid, 'detector_id':DETECTOR_ID,'detector_version':DETECTOR_VERSION,
                'type':f"{primary['axis']}_port_scan_pattern",
                'title':('TCP destination port sweep'
                         if primary['axis']=='vertical' else
                         'TCP multiple-host probe sweep'),
                'subject':primary['subject'],
                'observed_first_ns':first,'observed_last_ns':last,
                'description':('Distinct destination ports or hosts were probed with TCP SYN. '
                               'Missing replies and explicit matching RST refusals are counted separately.'
                               + (' A dense sweep of adjacent targets with completed, short, '
                                  'payload-free TCP handshakes was also observed.'
                                  if outcome_counts['observed_handshake'] else '')),
                'interpretation':('Observed TCP probing geometry; completed empty connections '
                                  'do not establish malicious intent.'
                                  if outcome_counts['observed_handshake'] else
                                  'Observed TCP probing pattern.'),
                'primary_evidence_id':eids[0], 'supporting_evidence_ids':eids[1:],
                'observed_axes':candidate_axes,
                'flow_count':len(all_flow_ids),
                'packet_frame_samples':_first_frames(db,ordered_flow_ids),
                'packet_frame_samples_truncated':len(all_flow_ids)>16,
                'complete_flow_provenance':'detector_finding_flows -> flow_packets -> packets',
                'limitations':[
                    'SYN with no observed reply is not proof of closed or filtered port.',
                    'Asymmetric/incomplete captures can hide SYN-ACK or RST responses.',
                    'Repeated retries dominate some traffic; diversity/attempt ratio is checked.',
                    ('Only dense, short, payload-free completed handshake sweeps '
                     'are included; other established connections are excluded.'
                     if outcome_counts['observed_handshake'] else
                     'Successful TCP connections are excluded to reduce false positives.'),
                    'Capture-local behavior only; no whitelist, P2P classification, or threat attribution.',
                    'UDP port scanning is not assessed by this detector.']}
            db.execute('INSERT INTO detector_findings VALUES(?,?,?)',
                       (fid,primary['evaluation_id'],_json(finding)))
            db.executemany('INSERT INTO detector_finding_flows VALUES(?,?)',
                           ((fid,x) for x in ordered_flow_ids))
            counters['finding_count']+=1
            if len(preview_findings)<max_json_findings: preview_findings.append(finding)
        db.commit()
        return {
            'detector_id':DETECTOR_ID,'version':DETECTOR_VERSION,
            'reference':'Observed TCP SYN and response evidence',
            'evaluation_scope':('capture-local SYN-only/RST-refused attempts and '
                'high-confidence dense, payload-free completed IPv4 connect sweeps; sliding windows'),
            'parameters':asdict(cfg),
            'summary':dict(sorted(dict(evaluations,**counters).items())),
            'findings':preview_findings,'evidence':preview_evidence,
            'nonfinding_evaluations_preview':evaluation_preview,
            'findings_preview_truncated':counters['finding_count']>max_json_findings,
            'full_provenance_index':str(index_path),'no_threat_scores_exposed':True,
            'limitations':['UDP excluded; no TCP packet reassembly.']}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
