"""Evidence-grounded finding grouping, not a new attack detector.

Only overlapping observations with *shared flow IDs* may form one case. Shared
IP, same host or close timestamps alone never imply one event. Detector rows
and their scores/labels (none are exposed) remain unmodified. Cases provide
an analyst-facing primary observation and typed supporting observations.
"""
from __future__ import annotations
from collections import defaultdict
from pathlib import Path
import json
import sqlite3

from .features import _json
from .flows import _id

CORRELATION_VERSION='0.7.0'
# Specificity order is deterministic and is NOT a severity, confidence or risk score.
PREFERRED_TYPES=(
    'vertical_port_scan_pattern','horizontal_port_scan_pattern',
    'periodic_communication','concentrated_nxdomain_diversity',
    'long_lived_tcp_flow_observed','large_outbound_payload_observed',
)


def _preferred(finding: dict) -> tuple:
    name=finding['type']
    return ((PREFERRED_TYPES.index(name) if name in PREFERRED_TYPES else len(PREFERRED_TYPES)),
            finding['finding_id'])


def _overlap(a: dict,b: dict) -> bool:
    return a['observed_first_ns']<=b['observed_last_ns'] and b['observed_first_ns']<=a['observed_last_ns']


def correlate_findings(index_path: str | Path, capture: dict, *,max_json_cases: int=25) -> dict:
    if max_json_cases<0:raise ValueError('max_json_cases must be nonnegative')
    db=sqlite3.connect(str(index_path));db.row_factory=sqlite3.Row
    try:
        row=db.execute('SELECT capture_id FROM feature_run LIMIT 1').fetchone()
        if row is None or row['capture_id']!=capture['capture_id']:
            raise ValueError('Missing/mismatched feature store')
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='correlation_run'").fetchone():
            raise FileExistsError('Correlation results already present; create fresh index')
        db.executescript('''
            CREATE TABLE correlation_run(version TEXT PRIMARY KEY,capture_id TEXT NOT NULL);
            CREATE TABLE correlation_cases(case_id TEXT PRIMARY KEY,primary_finding_id TEXT NOT NULL,
                data_json TEXT NOT NULL);
            CREATE TABLE correlation_case_members(case_id TEXT NOT NULL,finding_id TEXT NOT NULL,
                relation TEXT NOT NULL,PRIMARY KEY(case_id,finding_id));
            CREATE INDEX correlation_by_finding ON correlation_case_members(finding_id);
        ''')
        db.execute('INSERT INTO correlation_run VALUES(?,?)',(CORRELATION_VERSION,capture['capture_id']))
        findings=[json.loads(r[0]) for r in db.execute('SELECT finding_json FROM detector_findings ORDER BY finding_id')]
        if not findings:
            db.commit();return {'version':CORRELATION_VERSION,'summary':{'cases':0,'merged_cases':0,'raw_detector_findings':0},
                                'cases':[],'cases_preview_truncated':False,
                                'policy':'all_members_share_a_common_flow_and_overlapping_time_no_score',
                                'full_provenance_index':str(index_path)}
        # Strict complete-link evidence rule: every case member must share at
        # least one *same* flow AND a nonempty common time intersection. A-B,
        # B-C transitive chains are NOT automatically folded into A-B-C.
        flow_by_finding=defaultdict(set)
        for r in db.execute('SELECT finding_id,flow_id FROM detector_finding_flows ORDER BY finding_id,flow_id'):
            flow_by_finding[r['finding_id']].add(r['flow_id'])
        pending=sorted(findings,key=_preferred)
        groups=[]
        while pending:
            primary=pending.pop(0)
            group=[primary]
            common_flows=set(flow_by_finding[primary['finding_id']])
            common_start=primary['observed_first_ns']
            common_end=primary['observed_last_ns']
            leftovers=[]
            for candidate in pending:
                overlap_flows=common_flows & flow_by_finding[candidate['finding_id']]
                next_start=max(common_start,candidate['observed_first_ns'])
                next_end=min(common_end,candidate['observed_last_ns'])
                if overlap_flows and next_start<=next_end:
                    group.append(candidate)
                    common_flows=overlap_flows
                    common_start,common_end=next_start,next_end
                else:
                    leftovers.append(candidate)
            pending=leftovers
            groups.append(group)
        preview=[];merged=0
        for member_list in sorted(groups,key=lambda g:(min(f['observed_first_ns'] for f in g),
                                                               min(f['finding_id'] for f in g))):
            primary=min(member_list,key=_preferred)
            member_ids=sorted(f['finding_id'] for f in member_list)
            cid=_id('CA-',capture['capture_id'],member_ids)
            correlated=len(member_list)>1
            if correlated:merged+=1
            case={'case_id':cid,'primary_finding_id':primary['finding_id'],
                  'primary_title':primary['title'],'primary_type':primary['type'],
                  'primary_subject':primary['subject'],
                  'member_finding_ids':member_ids,
                  'supporting_findings':[{'finding_id':f['finding_id'],'detector_id':f['detector_id'],
                                          'type':f['type'],'title':f['title']}
                                         for f in member_list if f['finding_id']!=primary['finding_id']],
                  'observed_first_ns':min(f['observed_first_ns'] for f in member_list),
                  'observed_last_ns':max(f['observed_last_ns'] for f in member_list),
                  'relation_basis':('shared_flow_and_temporally_overlapping' if correlated else 'single_finding'),
                  'interpretation':primary['interpretation'],
                  'correlation_notes':('Supporting findings derive from overlapping traffic; '
                                       'they are not independent confirmations of malicious intent.' if correlated else
                                       'No detector correlation asserted.'),
                  'no_risk_score':True,'raw_findings_unchanged':True}
            db.execute('INSERT INTO correlation_cases VALUES(?,?,?)',(cid,primary['finding_id'],_json(case)))
            db.executemany('INSERT INTO correlation_case_members VALUES(?,?,?)',((cid,f['finding_id'],
                       'primary' if f['finding_id']==primary['finding_id'] else 'shared_flow_support') for f in member_list))
            if len(preview)<max_json_cases:preview.append(case)
        db.commit()
        return {'version':CORRELATION_VERSION,'summary':{'cases':len(groups),'merged_cases':merged,
                             'single_finding_cases':len(groups)-merged,
                             'raw_detector_findings':len(findings)},
                'cases':preview,'cases_preview_truncated':len(groups)>max_json_cases,
                'policy':'all_members_share_a_common_flow_and_overlapping_time_no_score',
                'full_provenance_index':str(index_path)}
    except Exception:
        db.rollback();raise
    finally:
        db.close()
