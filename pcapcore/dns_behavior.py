"""DNS NXDOMAIN observations from matched query-response transactions.

Runs on indexed capture observations. Ground-truth and IOC lists are not loaded.
Does not label domain generation algorithms, DNS tunnels or attack intent.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
import json
import sqlite3

from .beaconing import _schema
from .features import _json, NS
from .flows import _id

DETECTOR_ID = 'dns_nxdomain_diversity'
DETECTOR_VERSION = '0.5.0-experimental'


@dataclass(frozen=True)
class DNSParameters:
    sliding_window_seconds: int = 300
    min_distinct_nxdomain_names: int = 10
    min_nxdomain_fraction: float = 0.6
    max_group_events: int = 150_000

    def __post_init__(self):
        if (type(self.sliding_window_seconds) is not int or self.sliding_window_seconds <= 0 or
                type(self.min_distinct_nxdomain_names) is not int or self.min_distinct_nxdomain_names < 2 or
                type(self.max_group_events) is not int or self.max_group_events < self.min_distinct_nxdomain_names or
                not 0 < self.min_nxdomain_fraction <= 1):
            raise ValueError('Invalid DNS detector parameters')


def _episodes(matched: list[dict], cfg: DNSParameters) -> list[dict]:
    """Return merged overlapping positive rolling-window indices and metrics."""
    nx = Counter()
    nx_events = 0
    left = 0
    episodes = []
    for right, event in enumerate(matched):
        if event['rcode'] == 3 and event['qname_normalized']:
            nx[event['qname_normalized']] += 1
            nx_events += 1
        while event['query_ts_ns'] - matched[left]['query_ts_ns'] > cfg.sliding_window_seconds * NS:
            prior = matched[left]
            if prior['rcode'] == 3 and prior['qname_normalized']:
                nx[prior['qname_normalized']] -= 1
                nx_events -= 1
                if nx[prior['qname_normalized']] <= 0:
                    del nx[prior['qname_normalized']]
            left += 1
        size = right - left + 1
        if len(nx) >= cfg.min_distinct_nxdomain_names and nx_events / size >= cfg.min_nxdomain_fraction:
            if episodes and left <= episodes[-1]['end']:
                episodes[-1]['end'] = right
                episodes[-1]['peak_distinct_nxdomain'] = max(episodes[-1]['peak_distinct_nxdomain'],len(nx))
            else:
                episodes.append({'start':left,'end':right,'peak_distinct_nxdomain':len(nx)})
    for episode in episodes:
        selection = matched[episode['start']:episode['end']+1]
        verified = [e for e in selection if e['rcode'] == 3 and e['qname_normalized']]
        episode.update(events=verified,
                       first_ns=selection[0]['query_ts_ns'],
                       last_ns=selection[-1]['query_ts_ns'],
                       matched_query_count=len(selection),
                       verified_nxdomain_count=len(verified),
                       distinct_nxdomain_count=len(set(e['qname_normalized'] for e in verified)))
    return episodes


def analyze_dns_behavior(index_path: str | Path, capture: dict, *,
                         parameters: DNSParameters | None = None,
                         max_json_findings: int = 25,
                         max_json_evaluations: int = 25) -> dict:
    cfg = parameters or DNSParameters()
    if max_json_findings < 0 or max_json_evaluations < 0:
        raise ValueError('JSON preview limits must be nonnegative')
    db = sqlite3.connect(str(index_path)); db.row_factory = sqlite3.Row
    try:
        run=db.execute('SELECT capture_id FROM feature_run LIMIT 1').fetchone()
        if run is None or run['capture_id'] != capture['capture_id']:
            raise ValueError('Missing/mismatched feature store')
        _schema(db)
        db.executescript('''
            CREATE TABLE IF NOT EXISTS detector_finding_packets (
                finding_id TEXT NOT NULL, frame_no INTEGER NOT NULL, evidence_role TEXT NOT NULL,
                PRIMARY KEY(finding_id,frame_no,evidence_role));
            CREATE INDEX IF NOT EXISTS detector_finding_packets_by_frame ON detector_finding_packets(frame_no);
            CREATE TABLE IF NOT EXISTS detector_finding_dns_events (
                finding_id TEXT NOT NULL, event_id TEXT NOT NULL,
                PRIMARY KEY(finding_id,event_id));
        ''')
        if db.execute('SELECT 1 FROM detector_runs WHERE detector_id=?',(DETECTOR_ID,)).fetchone():
            raise FileExistsError('DNS detector already run; fresh index required')
        db.execute('INSERT INTO detector_runs VALUES(?,?,?,?)',
                   (DETECTOR_ID,DETECTOR_VERSION,capture['capture_id'],_json(asdict(cfg))))
        groups=defaultdict(list)
        for row in db.execute("SELECT event_id,data_json FROM events WHERE event_kind='dns' ORDER BY packet_frame,event_id"):
            item=json.loads(row['data_json']); item['event_id']=row['event_id']
            # Response-only records have no observed client-side query.
            if item.get('query_packet_ref') is not None:
                groups[(item['client_ip'],item['resolver_ip'])].append(item)
        counters=Counter({'finding_count':0}); finding_preview=[]; evidence_preview=[]; eval_preview=[]
        for (client,resolver),items in sorted(groups.items()):
            subject={'client_ip':client,'resolver_ip':resolver,'scope':'observed_client_resolver_pair'}
            gid=_id('DG-',capture['capture_id'],client,resolver)
            evaluation_id=_id('DE-',capture['capture_id'],DETECTOR_ID,gid)
            matched=sorted((e for e in items if e['match_status']=='matched' and e['rcode'] is not None
                           and e['query_ts_ns'] is not None),key=lambda e:(e['query_ts_ns'],e['query_packet_ref']))
            metrics={'observed_query_count':len(items),'matched_response_count':len(matched),
                     'unanswered_query_count':sum(e['match_status']=='unanswered' for e in items),
                     'ambiguous_query_count':sum(e['match_status']=='ambiguous' for e in items),
                     'total_verified_nxdomain_count':sum(e['rcode']==3 for e in matched),
                     'total_distinct_verified_nxdomain_names':len({e['qname_normalized'] for e in matched if e['rcode']==3 and e['qname_normalized']}),
                     'window_seconds':cfg.sliding_window_seconds}
            reasons=[];status='not_detected'; episodes=[]
            if len(items)>cfg.max_group_events:
                status='insufficient_data';reasons=['dns_group_exceeds_bounded_analysis_limit']
            elif len(matched)<cfg.min_distinct_nxdomain_names:
                status='insufficient_data';reasons=['too_few_matched_dns_responses']
            else:
                episodes=_episodes(matched,cfg)
                if episodes:
                    status='detected';reasons=['repeated_distinct_matched_nxdomain_in_sliding_window']
                elif metrics['unanswered_query_count']>len(matched):
                    status='limited_visibility';reasons=['many_queries_without_observed_responses']
                else:
                    reasons=['no_concentrated_distinct_nxdomain_pattern']
            metrics['qualifying_episodes']=len(episodes)
            db.execute('INSERT INTO detector_evaluations VALUES(?,?,?,?,?)',
                       (evaluation_id,gid,status,_json(reasons),_json(metrics)))
            counters[status]+=1
            if status!='detected' and len(eval_preview)<max_json_evaluations:
                eval_preview.append({'evaluation_id':evaluation_id,'subject':subject,'status':status,'reasons':reasons})
            for episode in episodes:
                qualifying=episode['events']
                # IDs identify exact transaction set; avoid merging independent episodes.
                eidlist=tuple(e['event_id'] for e in qualifying)
                finding_id=_id('FI-',capture['capture_id'],DETECTOR_ID,client,resolver,eidlist)
                evidence_id=_id('EV-',finding_id,'verified_nxdomain_transactions')
                frames=sorted({x for e in qualifying for x in (e['query_packet_ref'],e['response_packet_ref']) if x is not None})
                ev={'evidence_id':evidence_id,'finding_id':finding_id,'evaluation_id':evaluation_id,
                    'type':'matched_nxdomain_query_diversity',
                    'metrics':{'distinct_negative_qnames':episode['distinct_nxdomain_count'],
                               'matched_negative_response_count':episode['verified_nxdomain_count'],
                               'matched_response_count_in_episode':episode['matched_query_count'],
                               'window_seconds':cfg.sliding_window_seconds,
                               'peak_distinct_negative_qnames_in_window':episode['peak_distinct_nxdomain'],
                               'response_matching_required':True}}
                finding={'finding_id':finding_id,'detector_id':DETECTOR_ID,'detector_version':DETECTOR_VERSION,
                         'type':'concentrated_nxdomain_diversity','title':'NXDOMAIN responses across distinct queried names',
                         'subject':subject,'observed_first_ns':episode['first_ns'],
                         'observed_last_ns':episode['last_ns'],
                         'description':'Distinct DNS questions received matched NXDOMAIN responses within one client-resolver pair.',
                         'interpretation':'Observed DNS name-resolution failure diversity.',
                         'primary_evidence_id':evidence_id,'supporting_evidence_ids':[],
                         'flow_count':0,'packet_frame_samples':frames[:16],
                         'packet_frame_samples_truncated':len(frames)>16,
                         'complete_packet_provenance':'detector_finding_packets -> packets',
                         'limitations':['Unmatched queries are not treated as NXDOMAIN.',
                                        'No Public Suffix List grouping or tunneling claim.',
                                        'Source notes and IOC lists are not available to the detector.',
                                        'Thresholds are provisional until independent positive/benign evaluation.']}
                db.execute('INSERT INTO detector_evidence VALUES(?,?,?,?)',(evidence_id,evaluation_id,ev['type'],_json(ev)))
                db.execute('INSERT INTO detector_findings VALUES(?,?,?)',(finding_id,evaluation_id,_json(finding)))
                db.executemany('INSERT INTO detector_finding_dns_events VALUES(?,?)',((finding_id,e['event_id']) for e in qualifying))
                db.executemany('INSERT INTO detector_finding_packets VALUES(?,?,?)',(
                    (finding_id,e['query_packet_ref'],'query') for e in qualifying))
                db.executemany('INSERT INTO detector_finding_packets VALUES(?,?,?)',(
                    (finding_id,e['response_packet_ref'],'response') for e in qualifying if e['response_packet_ref'] is not None))
                flow_ids=[r[0] for r in db.execute('SELECT DISTINCT fp.flow_id FROM flow_packets fp '
                                                   'JOIN detector_finding_packets p ON fp.frame_no=p.frame_no '
                                                   'WHERE p.finding_id=?',(finding_id,))]
                db.executemany('INSERT INTO detector_finding_flows VALUES(?,?)',((finding_id,f) for f in flow_ids))
                finding['flow_count']=len(flow_ids)
                # Keep persistent and preview semantics in agreement.
                db.execute('UPDATE detector_findings SET finding_json=? WHERE finding_id=?',(_json(finding),finding_id))
                counters['finding_count']+=1
                if len(finding_preview)<max_json_findings: finding_preview.append(finding)
                if len(evidence_preview)<max_json_findings*3: evidence_preview.append(ev)
        db.commit()
        return {'detector_id':DETECTOR_ID,'version':DETECTOR_VERSION,
                'reference':'Matched DNS query and response evidence',
                'summary':dict(sorted(counters.items())),'parameters':asdict(cfg),
                'findings':finding_preview,'evidence':evidence_preview,
                'nonfinding_evaluations_preview':eval_preview,
                'findings_preview_truncated':counters['finding_count']>max_json_findings,
                'full_provenance_index':str(index_path),'no_threat_scores_exposed':True,
                'limitations':['Matched UDP DNS transactions only; TCP DNS unavailable.',
                               'Not a DNS tunneling detection; thresholds are experimental.']}
    except Exception:
        db.rollback();raise
    finally:
        db.close()
