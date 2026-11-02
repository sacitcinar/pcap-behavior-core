"""Evidence-preserving, conservative *presentation* grouping for synchronous scan cases.

No detector reads episode data. Findings, original cases and their provenance never
change. A parent episode is an association of concurrent observations, **not** an
assertion that all child findings are one attack or that their targets overlap.
"""
from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import sqlite3

from .features import _json
from .flows import _id

EPISODE_VERSION = '0.10.0'
SYNC_LIMIT_NS = 2_000_000_000
MIN_COMMON_TIME_FRACTION = 0.80
MIN_PORTS = 3
SCAN_TYPES = frozenset({'horizontal_port_scan_pattern'})


def _eligible(case: dict, finding: dict) -> bool:
    subject = finding.get('subject') or {}
    return (len(case['member_finding_ids']) == 1
            and case['primary_finding_id'] == finding.get('finding_id')
            and finding.get('type') in SCAN_TYPES
            and finding.get('detector_id') == 'tcp_port_scan_patterns'
            and subject.get('scan_axis') == 'horizontal'
            and subject.get('protocol') == 'tcp'
            and isinstance(subject.get('origin_ip'), str)
            and bool(subject['origin_ip'])
            and isinstance(subject.get('responder_port'), int)
            and 0 <= subject['responder_port'] <= 65535
            and isinstance(finding.get('observed_first_ns'), int)
            and isinstance(finding.get('observed_last_ns'), int)
            and finding['observed_first_ns'] < finding['observed_last_ns'])


def _synchronous(group: list[dict], candidate: dict) -> bool:
    all_items = group + [candidate]
    starts = [x['first'] for x in all_items]
    ends = [x['last'] for x in all_items]
    common = min(ends) - max(starts)
    longest = max(e - s for s, e in zip(starts, ends))
    return (common > 0 and common / longest >= MIN_COMMON_TIME_FRACTION
            and max(starts) - min(starts) <= SYNC_LIMIT_NS
            and max(ends) - min(ends) <= SYNC_LIMIT_NS
            and len({x['port'] for x in all_items}) == len(all_items))


def _targets(db: sqlite3.Connection, fid: str) -> set[str]:
    # Scan evidence is read from the full finding->flow link, NEVER a JSON preview.
    # This does not itself establish intent or campaign identity.
    targets: set[str] = set()
    rows = db.execute('''SELECT f.data_json FROM detector_finding_flows x
                         JOIN flows f ON f.flow_id=x.flow_id
                         WHERE x.finding_id=? ORDER BY x.flow_id''', (fid,))
    for (raw,) in rows:
        ip = json.loads(raw).get('responder_ip')
        if ip is not None:
            targets.add(ip)
    return targets


def associate_scan_episodes(index_path: str | Path, capture: dict,
                            *, max_json_episodes: int = 20) -> dict:
    """Append case-episode tables. Original cases/findings and membership stay intact."""
    if type(max_json_episodes) is not int or max_json_episodes < 0:
        raise ValueError('max_json_episodes must be a nonnegative integer')
    db = sqlite3.connect(str(index_path))
    try:
        run = db.execute('SELECT capture_id FROM correlation_run LIMIT 1').fetchone()
        if not run or run[0] != capture['capture_id']:
            raise ValueError('Missing or mismatched correlation run')
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='case_episode_run'").fetchone():
            raise FileExistsError('Episode grouping already present; use a fresh SQLite index')
        all_cases = {json.loads(raw)['case_id']: json.loads(raw)
                     for (raw,) in db.execute('SELECT data_json FROM correlation_cases')}
        all_findings = {fid: json.loads(raw) for fid, raw in db.execute(
            'SELECT finding_id,finding_json FROM detector_findings')}
        per_host: dict[str, list[dict]] = defaultdict(list)
        for cid, case in all_cases.items():
            fid = case['primary_finding_id']
            finding = all_findings.get(fid)
            if finding is None or not _eligible(case, finding):
                continue
            # No parent association without indexed flow provenance.
            if not db.execute('SELECT 1 FROM detector_finding_flows WHERE finding_id=? LIMIT 1',
                              (fid,)).fetchone():
                continue
            subject = finding['subject']
            per_host[subject['origin_ip']].append({
                'case_id': cid, 'finding_id': fid, 'origin': subject['origin_ip'],
                'port': subject['responder_port'],
                'first': finding['observed_first_ns'],
                'last': finding['observed_last_ns'],
                'frames': finding.get('packet_frame_samples') or [],
            })
        groups: list[list[dict]] = []
        for _origin, rows in sorted(per_host.items()):
            remaining = sorted(rows, key=lambda x: (x['first'], x['last'], x['port'], x['case_id']))
            while remaining:
                anchor = remaining.pop(0)
                group = [anchor]
                leftovers = []
                for item in remaining:
                    if _synchronous(group, item):
                        group.append(item)
                    else:
                        leftovers.append(item)
                remaining = leftovers
                if len({x['port'] for x in group}) >= MIN_PORTS:
                    groups.append(group)
        # All writes run in one transaction without modifying detector output.
        db.executescript('''
            CREATE TABLE case_episode_run(version TEXT PRIMARY KEY, capture_id TEXT NOT NULL);
            CREATE TABLE case_episodes(episode_id TEXT PRIMARY KEY,data_json TEXT NOT NULL);
            CREATE TABLE case_episode_members(episode_id TEXT NOT NULL,case_id TEXT NOT NULL UNIQUE,
                relation TEXT NOT NULL,PRIMARY KEY(episode_id,case_id));
            CREATE INDEX episode_members_by_case ON case_episode_members(case_id);
        ''')
        db.execute('INSERT INTO case_episode_run VALUES(?,?)',
                   (EPISODE_VERSION, capture['capture_id']))
        preview: list[dict] = []
        associated = 0
        for group in sorted(groups, key=lambda g: (min(x['first'] for x in g), g[0]['origin'])):
            member_case_ids = sorted(x['case_id'] for x in group)
            member_finding_ids = sorted(x['finding_id'] for x in group)
            eid = _id('EP-', capture['capture_id'], member_case_ids)
            target_sets = [_targets(db, x['finding_id']) for x in group]
            seen = set()
            duplicate_target_ips = set()
            for target_set in target_sets:
                duplicate_target_ips |= seen & target_set
                seen |= target_set
            frame_samples = sorted({int(n) for x in group for n in x['frames'][:4]})[:24]
            episode = {
                'episode_id': eid, 'kind': 'synchronous_horizontal_scan_case_group',
                'title': 'Synchronous multi-port probe observations',
                'origin_ip': group[0]['origin'], 'protocol': 'tcp',
                'ports': sorted(x['port'] for x in group),
                'member_case_ids': member_case_ids,
                'member_finding_ids': member_finding_ids,
                'observed_first_ns': min(x['first'] for x in group),
                'observed_last_ns': max(x['last'] for x in group),
                'shared_time_first_ns': max(x['first'] for x in group),
                'shared_time_last_ns': min(x['last'] for x in group),
                'distinct_target_ips_across_members': len(seen),
                'target_ips_seen_in_multiple_members': len(duplicate_target_ips),
                'packet_frame_samples': frame_samples,
                'relation_basis': 'same_origin_horizontal_syn_patterns_synchronous_starts_and_ends',
                'interpretation': ('Same-source horizontal probe patterns have closely aligned start and end times. '
                                   'Their evidence remains separate.'),
                'evidence_boundary': ('Member observations retain their distinct flow and target evidence.'),
                'no_risk_score': True, 'raw_findings_unchanged': True,
                'cases_unchanged': True,
            }
            db.execute('INSERT INTO case_episodes VALUES(?,?)', (eid, _json(episode)))
            db.executemany('INSERT INTO case_episode_members VALUES(?,?,?)',
                           ((eid, cid, 'concurrent_presentation_only') for cid in member_case_ids))
            associated += len(member_case_ids)
            if len(preview) < max_json_episodes:
                preview.append(episode)
        db.commit()
        return {
            'version': EPISODE_VERSION,
            'summary': {'parent_episodes': len(groups),
                        'associated_existing_cases': associated,
                        'original_cases_unchanged': len(all_cases),
                        'original_findings_unchanged': len(all_findings)},
            'episodes': preview, 'episodes_preview_truncated': len(groups) > max_json_episodes,
            'policy': 'concurrent_scan_case_presentation_only_never_merges_findings',
            'full_provenance_index': str(index_path),
        }
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
