"""Observational host and DNS evidence context.

Crucial semantics: an address is not a verified physical host, an observed
initiator is not always a proven origin, a common initiator is NOT evidence of
one attack, and a matched NXDOMAIN is NOT a DGA/tunnel diagnosis.
Detector and case tables are read-only to this layer; context has new tables.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from ipaddress import ip_address
import json
from pathlib import Path
import sqlite3

from .flows import _id
from .features import _json

CONTEXT_VERSION = '0.11.0-observational'


def _table(db: sqlite3.Connection, name: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _observed_initiator(subject: dict) -> tuple[str | None, str | None]:
    """Never identify a server IP as the origin just because it is present."""
    for role, field in (('dns_client', 'client_ip'), ('flow_origin', 'origin_ip'),
                        ('configured_local_source', 'local_ip')):
        address = subject.get(field)
        if isinstance(address, str):
            try:
                ip_address(address)
            except ValueError:
                continue
            return address, role
    return None, None


def _peer(subject: dict) -> str | None:
    for field in ('resolver_ip', 'responder_ip', 'nonconfigured_destination_ip'):
        value = subject.get(field)
        if isinstance(value, str):
            try:
                ip_address(value)
            except ValueError:
                continue
            return value
    return None


def _count_dict(counter: Counter) -> dict:
    return {str(key): counter[key] for key in sorted(counter, key=str)}


def attach_host_dns_context(index_path: str | Path, capture: dict, *,
                            max_json_hosts: int = 20,
                            max_json_dns: int = 20) -> dict:
    """Add separate contextual tables; preserve all existing findings/cases/frames.

    JSON is a bounded preview, but the complete context and its finding links are
    in SQLite. No IOC, domain suffix guessing, inferred intent, or numerical risk.
    """
    if (type(max_json_hosts) is not int or max_json_hosts < 0 or
            type(max_json_dns) is not int or max_json_dns < 0):
        raise ValueError('Context JSON preview limits must be nonnegative integers')
    db = sqlite3.connect(str(index_path))
    db.row_factory = sqlite3.Row
    try:
        if not _table(db, 'correlation_run') or not _table(db, 'feature_run'):
            raise ValueError('Host and DNS context requires a completed correlation and feature index')
        corr = db.execute('SELECT capture_id FROM correlation_run LIMIT 1').fetchone()
        feat = db.execute('SELECT capture_id FROM feature_run LIMIT 1').fetchone()
        if not corr or not feat or corr['capture_id'] != capture['capture_id'] or feat['capture_id'] != capture['capture_id']:
            raise ValueError('Capture ID does not match correlation/feature index')
        if _table(db, 'context_run'):
            raise FileExistsError('Context already attached; fresh index required')

        by_host = defaultdict(list)
        by_host_peer = defaultdict(set)
        linked_case = defaultdict(set)
        for row in db.execute('SELECT finding_id,case_id FROM correlation_case_members ORDER BY finding_id,case_id'):
            linked_case[row['finding_id']].add(row['case_id'])
        dns_records = []
        for row in db.execute('SELECT finding_id,finding_json FROM detector_findings ORDER BY finding_id'):
            f = json.loads(row['finding_json'])
            if f['finding_id'] != row['finding_id']:
                raise ValueError('Finding ID mismatch in evidence store')
            subject = f.get('subject') or {}
            address, role = _observed_initiator(subject)
            peer = _peer(subject)
            if address is not None:
                record = {'finding_id':row['finding_id'], 'detector_id':f['detector_id'],
                          'type':f['type'], 'initiator_role':role,
                          'explicit_peer_ip':peer,
                          'case_ids':sorted(linked_case[row['finding_id']])}
                by_host[address].append(record)
                if peer is not None:
                    by_host_peer[address].add(peer)
            if f['type'] == 'concentrated_nxdomain_diversity':
                dns_records.append(f)

        # Baseline visibility is for *observed client->resolver* pairs only.
        # Response-only observations are not treated as unanswered queries.
        selected_pairs = {(f['subject']['client_ip'],f['subject']['resolver_ip']) for f in dns_records}
        pair_stats = defaultdict(Counter)
        for row in db.execute("SELECT data_json FROM events WHERE event_kind='dns' ORDER BY packet_frame,event_id"):
            event = json.loads(row['data_json'])
            pair = event.get('client_ip'), event.get('resolver_ip')
            if pair not in selected_pairs:
                continue
            stat = pair_stats[pair]
            if event.get('query_packet_ref') is None:
                stat['response_without_observed_query'] += 1
                continue
            stat['observed_queries'] += 1
            status = event.get('match_status')
            if status == 'matched':
                stat['matched_responses'] += 1
                if event.get('rcode') == 3:
                    stat['matched_nxdomain_responses'] += 1
            elif status == 'unanswered':
                stat['unanswered_queries'] += 1
            elif status == 'ambiguous':
                stat['ambiguous_queries'] += 1
            else:
                stat['other_query_match_states'] += 1

        # Transactional DDL: a corrupt evidence link must leave NO partial
        # context tables behind in a caller's index. executescript() would
        # implicitly commit the transaction and break this guarantee.
        db.execute('BEGIN')
        for ddl in (
            'CREATE TABLE context_run(version TEXT NOT NULL, capture_id TEXT NOT NULL, policy TEXT NOT NULL)',
            'CREATE TABLE context_hosts(host_ip TEXT PRIMARY KEY, data_json TEXT NOT NULL)',
            'CREATE TABLE context_host_findings(host_ip TEXT NOT NULL, finding_id TEXT NOT NULL, initiator_role TEXT NOT NULL, PRIMARY KEY(host_ip,finding_id))',
            'CREATE INDEX context_host_findings_by_finding ON context_host_findings(finding_id)',
            'CREATE TABLE context_dns_findings(finding_id TEXT PRIMARY KEY, data_json TEXT NOT NULL)',
        ):
            db.execute(ddl)
        db.execute('INSERT INTO context_run VALUES(?,?,?)',
                   (CONTEXT_VERSION,capture['capture_id'],'observational_context_no_attribution_no_merging'))
        dns_preview = []
        for f in sorted(dns_records,key=lambda x:x['finding_id']):
            fid = f['finding_id']
            subject = f['subject']
            peer = subject['client_ip'],subject['resolver_ip']
            linked = list(db.execute('''SELECT e.event_id,e.data_json FROM detector_finding_dns_events r
                             JOIN events e ON e.event_id=r.event_id WHERE r.finding_id=?
                             ORDER BY e.packet_frame,e.event_id''',(fid,)))
            if not linked:
                raise ValueError('DNS finding has no exact linked DNS transaction evidence')
            name_set = set()
            qtypes=Counter()
            frame_set = set()
            for row in linked:
                e=json.loads(row['data_json'])
                if (e.get('match_status')!='matched' or e.get('rcode')!=3
                    or e.get('query_packet_ref') is None or e.get('response_packet_ref') is None
                    or (e.get('client_ip'),e.get('resolver_ip'))!=peer):
                    raise ValueError('DNS finding references a transaction without verified matched NXDOMAIN evidence')
                qtypes[e['qtype']]+=1
                name_set.add(e['qname_normalized'])
                frame_set.update((e['query_packet_ref'],e['response_packet_ref']))
            # Validate direct packet links, not just the transaction's JSON.
            indexed_frames={row[0] for row in db.execute(
                'SELECT frame_no FROM detector_finding_packets WHERE finding_id=?',(fid,))}
            if frame_set != indexed_frames:
                raise ValueError('DNS finding packet references differ from its linked transaction frames')
            observation=_count_dict(pair_stats[peer])
            for name in ('observed_queries','matched_responses','matched_nxdomain_responses',
                         'unanswered_queries','ambiguous_queries','response_without_observed_query'):
                observation.setdefault(name,0)
            datum={'finding_id':fid,'client_ip':peer[0],'resolver_ip':peer[1],
                   'exact_matched_nxdomain_transaction_count':len(linked),
                   'exact_distinct_negative_name_count':len(name_set),
                   'qtype_counts_in_qualifying_transactions':_count_dict(qtypes),
                   'direct_query_response_frame_count':len(frame_set),
                   'direct_frame_samples':sorted(frame_set)[:16],
                   'frame_samples_truncated':len(frame_set)>16,
                   'client_resolver_capture_context':observation,
                   'matched_fraction_denominator':'matched_responses_only; no inferred NXDOMAIN from unanswered',
                   'registered_domain_grouping':'not_performed_psl_required',
                   'interpretation':'Only matching DNS response evidence; no DGA, tunnel, malware or domain-to-TCP linkage claim.',
                   'full_dns_event_provenance':'detector_finding_dns_events -> events',
                   'full_frame_provenance':'detector_finding_packets -> packets'}
            db.execute('INSERT INTO context_dns_findings VALUES(?,?)',(fid,_json(datum)))
            if len(dns_preview)<max_json_dns:
                dns_preview.append(datum)

        host_preview=[]
        for host_ip, records in sorted(by_host.items()):
            types=Counter(r['type'] for r in records)
            roles=Counter(r['initiator_role'] for r in records)
            peer_ips=sorted(by_host_peer[host_ip])
            periodic_peers={r['explicit_peer_ip'] for r in records if r['type']=='periodic_communication'
                            and r['explicit_peer_ip'] is not None}
            profile_row=db.execute('SELECT metrics_json FROM feature_hosts WHERE host_ip=?',(host_ip,)).fetchone()
            dns_row=db.execute('SELECT metrics_json FROM feature_dns_clients WHERE client_ip=?',(host_ip,)).fetchone()
            profile=json.loads(profile_row[0]) if profile_row else None
            dns_profile=json.loads(dns_row[0]) if dns_row else None
            data={'host_ip':host_ip,'finding_count':len(records),
                  'existing_case_count':len({cid for r in records for cid in r['case_ids']}),
                  'finding_type_counts':_count_dict(types),
                  'initiator_role_counts':_count_dict(roles),
                  'distinct_explicit_peer_ip_count':len(peer_ips),
                  'explicit_peer_ip_samples':peer_ips[:16],
                  'peer_samples_truncated':len(peer_ips)>16,
                  'periodic_communication_distinct_peer_count':len(periodic_peers),
                  'independent_peer_caveat':('Multiple periodic peers must not be merged or labelled one C2 campaign.'
                     if len(periodic_peers)>1 else 'Same source IP alone does not prove a shared cause.'),
                  'origin_visibility_caveat':('Some flows had inferred rather than SYN-confirmed origin.'
                     if profile and profile['orientation_not_syn_confirmed_count'] else
                     'Address represents an observed flow origin/client, not a verified device.'),
                  'flow_origin_profile': ({k:profile.get(k) for k in (
                      'flow_count','unique_responder_ip_count','unique_protocol_port_count',
                      'orientation_not_syn_confirmed_count')} if profile else None),
                  'dns_client_profile':({k:dns_profile.get(k) for k in (
                      'query_count','matched_query_count','unmatched_query_count','ambiguous_query_count',
                      'unique_matched_nxdomain_qname_count')} if dns_profile else None),
                  'relationship':'same_observed_initiator_address_only_not_evidence_of_same_incident',
                  'complete_finding_provenance':'context_host_findings -> detector_findings'}
            db.execute('INSERT INTO context_hosts VALUES(?,?)',(host_ip,_json(data)))
            db.executemany('INSERT INTO context_host_findings VALUES(?,?,?)',
                           ((host_ip,r['finding_id'],r['initiator_role']) for r in records))
            if len(host_preview)<max_json_hosts:
                host_preview.append(data)
        db.commit()
        return {'version':CONTEXT_VERSION,
                'summary':{'observed_initiator_addresses_with_findings':len(by_host),
                           'raw_findings_linked_to_host_context':sum(map(len,by_host.values())),
                           'dns_findings_with_exact_transaction_context':len(dns_records),
                           'new_detector_findings':0,'new_correlation_cases':0},
                'hosts':host_preview,'dns_findings':dns_preview,
                'hosts_preview_truncated':len(by_host)>max_json_hosts,
                'dns_preview_truncated':len(dns_records)>max_json_dns,
                'link_policy':'common IP is contextual, never a correlation or attribution rule',
                'full_provenance_index':str(index_path)}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
