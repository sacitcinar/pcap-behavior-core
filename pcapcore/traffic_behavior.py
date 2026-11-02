"""Traffic-duration and explicit-CIDR outbound observations.

Values are measured from captured packets: first and last observation,
transport-layer payload and per-direction unique TCP sequence-byte estimates.
They are not application-byte totals or evidence of confirmed exfiltration.
No IOC lists, validation labels or threat scores are consulted.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from ipaddress import ip_address, ip_network
from pathlib import Path
import json
import sqlite3

from .beaconing import _schema, _first_frames
from .features import _json, NS
from .flows import _id

DETECTOR_ID = 'traffic_volume_and_duration'
DETECTOR_VERSION = '0.6.0-experimental'


@dataclass(frozen=True)
class TrafficParameters:
    min_long_flow_seconds: int = 1500
    min_egress_observed_l4_bytes: int = 100_000_000
    min_data_bearing_tcp_bytes: int = 1
    max_flow_records: int = 500_000

    def __post_init__(self):
        for k in ('min_long_flow_seconds','min_egress_observed_l4_bytes',
                  'min_data_bearing_tcp_bytes','max_flow_records'):
            if type(getattr(self,k)) is not int or getattr(self,k)<=0:
                raise ValueError(k+' must be a positive integer')


def analyze_traffic_behavior(index_path: str | Path, capture: dict, *,
                             parameters: TrafficParameters | None = None,
                             max_json_findings: int = 25,
                             max_json_evaluations: int = 25) -> dict:
    cfg=parameters or TrafficParameters()
    if max_json_findings < 0 or max_json_evaluations < 0:
        raise ValueError('JSON preview limits must be nonnegative')
    db=sqlite3.connect(str(index_path)); db.row_factory=sqlite3.Row
    try:
        run=db.execute('SELECT capture_id,parameters_json FROM feature_run LIMIT 1').fetchone()
        if not run or run['capture_id']!=capture['capture_id']:
            raise ValueError('Missing/mismatched completed feature store')
        _schema(db)
        # This table does not alter the indexed packet and flow observations.
        db.executescript('''CREATE TABLE IF NOT EXISTS detector_finding_packets (
            finding_id TEXT NOT NULL, frame_no INTEGER NOT NULL, evidence_role TEXT NOT NULL,
            PRIMARY KEY(finding_id,frame_no,evidence_role));
            CREATE INDEX IF NOT EXISTS detector_finding_packets_by_frame ON detector_finding_packets(frame_no);''')
        if db.execute('SELECT 1 FROM detector_runs WHERE detector_id=?',(DETECTOR_ID,)).fetchone():
            raise FileExistsError('Traffic detector already run; create a fresh SQLite index')
        db.execute('INSERT INTO detector_runs VALUES(?,?,?,?)',
                   (DETECTOR_ID,DETECTOR_VERSION,capture['capture_id'],_json(asdict(cfg))))
        limit=db.execute('SELECT COUNT(*) FROM flows').fetchone()[0]
        counters=Counter({'finding_count':0});finding_preview=[];evidence_preview=[];eval_preview=[]
        def evaluate(scope,subject,status,reason,metrics):
            gid=_id('TG-',capture['capture_id'],scope,subject)
            evaluation_id=_id('DE-',capture['capture_id'],DETECTOR_ID,gid)
            db.execute('INSERT INTO detector_evaluations VALUES(?,?,?,?,?)',
                       (evaluation_id,gid,status,_json([reason]),_json(metrics)))
            counters[status]+=1
            if status!='detected' and len(eval_preview)<max_json_evaluations:
                eval_preview.append({'evaluation_id':evaluation_id,'subject':subject,'status':status,'reasons':[reason]})
            return evaluation_id
        def save(finding,evidence,evaluation_id,flow_ids=(),frame_selector=None):
            fid=finding['finding_id']
            db.execute('INSERT INTO detector_findings VALUES(?,?,?)',(fid,evaluation_id,_json(finding)))
            db.execute('INSERT INTO detector_evidence VALUES(?,?,?,?)',
                       (evidence['evidence_id'],evaluation_id,evidence['type'],_json(evidence)))
            db.executemany('INSERT INTO detector_finding_flows VALUES(?,?)',((fid,f) for f in sorted(set(flow_ids))))
            if frame_selector is not None:
                src,dst=frame_selector
                db.execute("INSERT INTO detector_finding_packets(finding_id,frame_no,evidence_role) "
                           "SELECT ?,frame_no,'observed_egress_packet' FROM packets "
                           "WHERE src_ip=? AND dst_ip=? AND parse_status='ok' AND fragment_state IN ('unfragmented','atomic') AND COALESCE(l4_captured_payload_bytes,0)>0",(fid,src,dst))
            counters['finding_count']+=1
            if len(finding_preview)<max_json_findings:finding_preview.append(finding)
            if len(evidence_preview)<max_json_findings*3:evidence_preview.append(evidence)
        if limit>cfg.max_flow_records:
            evaluate('all',{'scope':'capture'},'insufficient_data','too_many_flow_records_no_sampling',
                     {'flow_count':limit,'max_flow_records':cfg.max_flow_records})
        else:
            flows=[json.loads(r[0]) for r in db.execute('SELECT data_json FROM flows ORDER BY flow_id')]
            # Long connection is per single *observed* TCP flow, not cumulative duration.
            for flow in flows:
                if flow['protocol']!='tcp':continue
                duration=flow['observed_duration_ns']
                subject={'origin_ip':flow['origin_ip'],'origin_port':flow['origin_port'],
                         'responder_ip':flow['responder_ip'],'responder_port':flow['responder_port'],
                         'protocol':'tcp','flow_id':flow['flow_id']}
                payload=flow['orig_l4_payload_observed_bytes']+flow['resp_l4_payload_observed_bytes']
                reliable=(flow['observed_tcp_state']=='observed_handshake'
                          and not (set(flow['flow_visibility_flags']) & {'time_anomaly','truncated_or_partial','fragmented'}))
                if duration<cfg.min_long_flow_seconds*NS:
                    status='not_detected';reason='observed_duration_below_threshold'
                elif not reliable:
                    status='limited_visibility';reason='long_duration_but_incomplete_handshake_or_capture'
                elif payload<cfg.min_data_bearing_tcp_bytes:
                    status='not_detected';reason='long_duration_without_observed_payload'
                else:
                    status='detected';reason='one_data_bearing_tcp_flow_observed_long_lived'
                metrics={'observed_duration_ns':duration,'captured_l4_payload_bytes':payload,
                         'observed_tcp_state':flow['observed_tcp_state'],
                         'flow_visibility_flags':flow['flow_visibility_flags']}
                eval_id=evaluate('long_tcp',subject,status,reason,metrics)
                if status!='detected':continue
                fid=_id('FI-',capture['capture_id'],DETECTOR_ID,'long_tcp',flow['flow_id'])
                eid=_id('EV-',fid,'duration')
                finding={'finding_id':fid,'detector_id':DETECTOR_ID,'detector_version':DETECTOR_VERSION,
                         'type':'long_lived_tcp_flow_observed','title':'Long-lived TCP flow observed',
                         'subject':subject,'observed_first_ns':flow['first_seen_ns'],
                         'observed_last_ns':flow['last_seen_ns'],
                         'description':'An established TCP flow carried payload over an extended observed interval.',
                         'interpretation':'Long duration and payload are descriptive traffic observations.',
                         'primary_evidence_id':eid,'supporting_evidence_ids':[],
                         'flow_count':1,'packet_frame_samples':flow['packet_refs_sample'],
                         'packet_frame_samples_truncated':flow['packet_ref_count']>len(flow['packet_refs_sample']),
                         'complete_flow_provenance':'detector_finding_flows -> flow_packets -> packets',
                         'limitations':['Observed flow lifetime, not true session lifetime.',
                                        'TCP idle timeout may split a single session.',
                                        'No protocol payload reassembly, malware attribution or risk score.']}
                evidence={'evidence_id':eid,'finding_id':fid,'evaluation_id':eval_id,
                          'type':'observed_single_tcp_flow_duration','metrics':metrics}
                save(finding,evidence,eval_id,flow_ids=[flow['flow_id']])
            # Network direction is never inferred; explicit CIDR config only.
            net_values=json.loads(run['parameters_json']).get('configured_local_cidrs',[])
            nets=tuple(ip_network(x,strict=False) for x in net_values)
            if not nets:
                evaluate('egress',{'scope':'capture','role':'egress'},'not_applicable',
                         'requires_explicit_local_cidrs',{'configured_local_cidrs':[]})
            else:
                # Use existing indexed packet metrics; do not parse PCAP again.
                # Packet-level direction works for responder-originated uploads too.
                rows=db.execute('''SELECT src_ip,dst_ip,COUNT(*) AS packet_count,
                                  SUM(COALESCE(l4_captured_payload_bytes,0)) AS l4_bytes,
                                  SUM(COALESCE(ip_declared_bytes,0)) AS declared_ip_bytes,
                                  MIN(ts_ns) AS first_ns,MAX(ts_ns) AS last_ns
                                  FROM packets WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
                                  AND parse_status='ok' AND fragment_state IN ('unfragmented','atomic')
                                  GROUP BY src_ip,dst_ip ORDER BY src_ip,dst_ip''').fetchall()
                flow_pairs=defaultdict(set)
                for f in flows:
                    flow_pairs[(f['origin_ip'],f['responder_ip'])].add(f['flow_id'])
                    flow_pairs[(f['responder_ip'],f['origin_ip'])].add(f['flow_id'])
                for r in rows:
                    src,dst=r['src_ip'],r['dst_ip']
                    if not any(ip_address(src) in n for n in nets) or any(ip_address(dst) in n for n in nets):
                        continue
                    subject={'local_ip':src,'nonconfigured_destination_ip':dst,
                             'scope':'configured_local_to_nonconfigured_address'}
                    metrics={'observed_l4_payload_bytes_including_retransmissions':r['l4_bytes'],
                             'declared_ip_bytes':r['declared_ip_bytes'],
                             'packet_count':r['packet_count'],
                             'first_packet_ns':r['first_ns'],'last_packet_ns':r['last_ns'],
                             'bytes_are_not_application_unique':True,
                             'excluded': 'malformed_partial_or_fragmented_packets'}
                    detected=r['l4_bytes']>=cfg.min_egress_observed_l4_bytes
                    status='detected' if detected else 'not_detected'
                    reason='large_observed_local_to_nonconfigured_payload' if detected else 'below_egress_payload_threshold'
                    eval_id=evaluate('egress',subject,status,reason,metrics)
                    if not detected:continue
                    fid=_id('FI-',capture['capture_id'],DETECTOR_ID,'egress',src,dst)
                    eid=_id('EV-',fid,'egress_bytes')
                    frames=[x[0] for x in db.execute('''SELECT frame_no FROM packets WHERE src_ip=? AND dst_ip=?
                          AND parse_status='ok' AND fragment_state IN ('unfragmented','atomic')
                          AND COALESCE(l4_captured_payload_bytes,0)>0 ORDER BY frame_no LIMIT 16''',(src,dst))]
                    flow_ids=flow_pairs[(src,dst)]
                    finding={'finding_id':fid,'detector_id':DETECTOR_ID,'detector_version':DETECTOR_VERSION,
                             'type':'large_outbound_payload_observed','title':'High outbound payload volume observed',
                             'subject':subject,'observed_first_ns':r['first_ns'],
                             'observed_last_ns':r['last_ns'],
                             'description':'High captured L4 payload volume from an explicitly configured local network to an external peer.',
                             'interpretation':'Observed outbound transfer volume; traffic intent is not inferred.',
                             'primary_evidence_id':eid,'supporting_evidence_ids':[],
                             'flow_count':len(flow_ids),'packet_frame_samples':frames,
                             'packet_frame_samples_truncated':r['packet_count']>len(frames),
                             'complete_packet_provenance':'detector_finding_packets -> packets',
                             'limitations':['CIDR assignment is supplied by analyst.',
                                            'Only successfully parsed, non-fragmented packets are counted; actual transfer may be larger.',
                                            'Captured L4 bytes include TCP retransmissions and do not prove application-level size.',
                                            'No exfiltration, unauthorized-transfer or data-content determination.',
                                            'No known-benign baseline for the configured network.']}
                    ev={'evidence_id':eid,'finding_id':fid,'evaluation_id':eval_id,
                        'type':'observed_local_to_nonconfigured_payload_volume','metrics':metrics}
                    save(finding,ev,eval_id,flow_ids=flow_ids,frame_selector=(src,dst))
        db.commit()
        return {'detector_id':DETECTOR_ID,'version':DETECTOR_VERSION,
                'reference':'Observed flow duration and captured outbound byte counts',
                'parameters':asdict(cfg),'summary':dict(sorted(counters.items())),
                'findings':finding_preview,'evidence':evidence_preview,
                'nonfinding_evaluations_preview':eval_preview,
                'findings_preview_truncated':counters['finding_count']>max_json_findings,
                'full_provenance_index':str(index_path),'no_threat_scores_exposed':True,
                'limitations':['Large transfer is an observation, never confirmed exfiltration.',
                               '25 minute duration and 100 MB volume thresholds are provisional.']}
    except Exception:
        db.rollback();raise
    finally:
        db.close()
