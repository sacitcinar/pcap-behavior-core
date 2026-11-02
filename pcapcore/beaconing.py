"""Conservative repeated-connection timing detector.

Uses observed flow-start intervals, interval dispersion, connection-size
consistency and capture-local timing continuity. Observations are grouped by
IP endpoints and ports. No IOC, malware taxonomy, external threat score or
validation label is consulted.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sqlite3
import statistics

from .features import _distribution, _json, NS
from .flows import _id

DETECTOR_ID = 'periodic_tcp_communication'
DETECTOR_VERSION = '0.17.0'


@dataclass(frozen=True)
class BeaconParameters:
    min_distinct_starts: int = 6
    min_observed_span_seconds: float = 60.0
    min_median_interval_seconds: float = 5.0
    max_relative_mad: float = 0.15
    max_cadence_gap_multiple: float = 3.0
    relative_interval_tolerance: float = 0.20
    min_intervals_in_band_fraction: float = 0.80
    min_handshake_fraction: float = 0.80
    min_data_flow_fraction: float = 0.60
    min_size_in_band_fraction: float = 0.75
    relative_size_tolerance: float = 0.20
    max_group_flows: int = 20000

    def __post_init__(self):
        if self.min_distinct_starts < 4 or self.max_group_flows < self.min_distinct_starts:
            raise ValueError('min_distinct_starts >=4 and max_group_flows >= min_distinct_starts required')
        for key in ('min_observed_span_seconds', 'min_median_interval_seconds',
                    'max_relative_mad', 'max_cadence_gap_multiple', 'relative_interval_tolerance',
                    'relative_size_tolerance'):
            if getattr(self, key) <= 0:
                raise ValueError(key+' must be >0')
        for key in ('min_intervals_in_band_fraction', 'min_handshake_fraction',
                    'min_data_flow_fraction', 'min_size_in_band_fraction'):
            value = getattr(self, key)
            if not 0 < value <= 1:
                raise ValueError(key+' must be between 0 and 1')


def _schema(db: sqlite3.Connection) -> None:
    db.executescript('''
        CREATE TABLE IF NOT EXISTS detector_runs (
            detector_id TEXT PRIMARY KEY, version TEXT NOT NULL,
            capture_id TEXT NOT NULL, parameters_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS detector_evaluations (
            evaluation_id TEXT PRIMARY KEY, group_id TEXT NOT NULL,
            status TEXT NOT NULL, reason_codes_json TEXT NOT NULL,
            metrics_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS detector_evaluations_by_group ON detector_evaluations(group_id);
        CREATE TABLE IF NOT EXISTS detector_evidence (
            evidence_id TEXT PRIMARY KEY, evaluation_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL, data_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS detector_findings (
            finding_id TEXT PRIMARY KEY, evaluation_id TEXT NOT NULL,
            finding_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS detector_finding_flows (
            finding_id TEXT NOT NULL, flow_id TEXT NOT NULL,
            PRIMARY KEY (finding_id, flow_id));
        CREATE INDEX IF NOT EXISTS detector_finding_flows_by_flow ON detector_finding_flows(flow_id);
    ''')


def _in_band_fraction(values: list[int], median: float, tolerance: float) -> float:
    if not values or median <= 0:
        return 0.0
    return sum(abs(x - median) <= median * tolerance for x in values) / len(values)


def _coherent_runs(starts: list[int], cfg: BeaconParameters) -> list[dict]:
    """Find contiguous, independently qualifying cadence windows.

    A majority-of-gaps statistic over the *whole capture* can hide an arbitrarily
    long silence. Test the existing timing criteria in consecutive windows of
    at least ``min_distinct_starts`` instead. A window may contain jitter or a
    missed cycle, but not a hiatus > the declared cadence multiple. Merge only
    windows sharing observed starts; never bridge a gap by endpoint identity.
    """
    width = cfg.min_distinct_starts
    spans: list[list[int]] = []
    for left in range(len(starts) - width + 1):
        right = left + width - 1
        gaps = [starts[k + 1] - starts[k] for k in range(left, right)]
        dist = _distribution(gaps)
        med = dist['median']
        if not med or med < cfg.min_median_interval_seconds * NS:
            continue
        if starts[right] - starts[left] < cfg.min_observed_span_seconds * NS:
            continue
        if max(gaps) > cfg.max_cadence_gap_multiple * med:
            continue
        if dist['mad'] / med > cfg.max_relative_mad:
            continue
        if _in_band_fraction(gaps, med, cfg.relative_interval_tolerance) < cfg.min_intervals_in_band_fraction:
            continue
        if spans and left <= spans[-1][1]:
            spans[-1][1] = right
        else:
            spans.append([left, right])
    runs = []
    for left, right in spans:
        gaps = [starts[k + 1] - starts[k] for k in range(left, right)]
        dist = _distribution(gaps)
        runs.append(dict(first_ns=starts[left], last_ns=starts[right],
                         distinct_start_count=right - left + 1,
                         median_interval_ns=dist['median'],
                         mad_interval_ns=dist['mad'],
                         observed_interval_count=len(gaps),
                         interval_max_ns=max(gaps),
                         intervals_in_band_fraction=round(_in_band_fraction(
                             gaps, dist['median'], cfg.relative_interval_tolerance), 6)))
    return runs


def _size_observation(members: list[dict], cfg: BeaconParameters) -> dict:
    # A single total can mask asymmetric communication. Both observed directions are recorded.
    output = {}
    for label, column in (('origin', 'orig_l4_payload_observed_bytes'),
                          ('responder', 'resp_l4_payload_observed_bytes')):
        values = [f[column] for f in members]
        dist = _distribution(values)
        median = dist['median']
        fraction = _in_band_fraction(values, median, cfg.relative_size_tolerance) if median else 0.0
        output[label] = dict(median_observed_l4_bytes=median,
                             mad_observed_l4_bytes=dist['mad'],
                             within_relative_tolerance_fraction=round(fraction, 6),
                             consistent=(median is not None and median > 0
                                         and fraction >= cfg.min_size_in_band_fraction),
                             sample_count=len(values),
                             measurement='captured_l4_payload_bytes_including_tcp_retransmissions')
    return output


def _first_frames(db: sqlite3.Connection, flow_ids: list[str], limit: int = 16) -> list[int]:
    # No huge SQL IN clause; use indexed relationship table in flow order.
    frames = []
    for fid in flow_ids:
        r = db.execute('SELECT MIN(frame_no) FROM flow_packets WHERE flow_id=?', (fid,)).fetchone()
        if r is not None and r[0] is not None:
            frames.append(r[0])
        if len(frames) == limit:
            break
    return frames


def analyze_periodic_communications(index_path: str | Path, capture: dict, *,
                                    parameters: BeaconParameters | None = None,
                                    max_json_findings: int = 25,
                                    max_json_evaluations: int = 25) -> dict:
    """Run only after extract_features() has completed, retaining full provenance.

    SQLite keeps all evaluations/findings/evidence and the *complete* linked flow
    set; JSON is only a bounded view. No classification of C2/malware is made.
    """
    cfg = parameters or BeaconParameters()
    if max_json_findings < 0 or max_json_evaluations < 0:
        raise ValueError('JSON limits must be non-negative')
    db = sqlite3.connect(str(index_path))
    db.row_factory = sqlite3.Row
    try:
        r = db.execute('SELECT capture_id FROM feature_run LIMIT 1').fetchone()
        if r is None or r['capture_id'] != capture['capture_id']:
            raise ValueError('Missing/mismatched completed feature store')
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detector_runs'").fetchone()
        if exists and db.execute('SELECT 1 FROM detector_runs LIMIT 1').fetchone():
            raise FileExistsError('Detector results already exist; use a fresh SQLite index')
        _schema(db)
        db.execute('INSERT INTO detector_runs VALUES (?,?,?,?)',
                   (DETECTOR_ID, DETECTOR_VERSION, capture['capture_id'], _json(asdict(cfg))))
        counters = Counter()
        counters['finding_count'] = 0  # Preserve zero explicitly in the stable result contract.
        finding_preview = []
        evidence_preview = []
        evaluation_preview = []
        capture_start = capture.get('first_ts_ns')
        capture_end = capture.get('last_ts_ns')
        span = (capture_end-capture_start) if capture_start is not None and capture_end is not None else 0

        for row in db.execute('SELECT group_id,subject_json,metrics_json FROM feature_groups ORDER BY group_id').fetchall():
            group_id = row['group_id']
            subject = json.loads(row['subject_json'])
            fm = json.loads(row['metrics_json'])
            eval_id = _id('DE-', capture['capture_id'], DETECTOR_ID, group_id)
            reasons = []
            status = 'not_detected'
            metrics = dict(flow_count=fm['flow_count'],
                           distinct_start_count=fm['distinct_start_count'],
                           protocol=subject['protocol'],
                           reference='Capture-local TCP interval and byte measurements')
            members = []
            if subject['protocol'] != 'tcp':
                status = 'not_applicable'; reasons.append('tcp_only')
            elif fm['flow_count'] > cfg.max_group_flows:
                status = 'insufficient_data'; reasons.append('group_exceeds_bounded_analysis_limit')
            elif fm['distinct_start_count'] < cfg.min_distinct_starts:
                status = 'insufficient_data'; reasons.append('too_few_distinct_connection_starts')
            else:
                # Ordering by JSON value is safe for these nonnegative timestamps;
                # Python sorts again to guarantee stable ties and input independence.
                members = [json.loads(f[0]) for f in db.execute(
                    'SELECT flows.data_json FROM feature_group_flows gf '
                    'JOIN flows ON flows.flow_id=gf.flow_id WHERE gf.group_id=?',(group_id,))]
                members.sort(key=lambda m:(m['first_seen_ns'],m['flow_id']))
                starts = sorted(set(f['first_seen_ns'] for f in members))
                # Deduplicate identical start times before measuring intervals
                # rather than treating parallel flows as repeated timing evidence.
                intervals = [b-a for a,b in zip(starts, starts[1:])]
                dist = _distribution(intervals)
                median_ns = dist['median']
                mad_ns = dist['mad']
                relative_mad = (mad_ns / median_ns) if median_ns else None
                fraction = _in_band_fraction(intervals, median_ns, cfg.relative_interval_tolerance)
                observed_span_ns = starts[-1]-starts[0]
                handshake_count = sum(f['observed_tcp_state']=='observed_handshake' for f in members)
                data_flow_count = sum(f['orig_l4_payload_observed_bytes'] > 0 or
                                      f['resp_l4_payload_observed_bytes'] > 0 for f in members)
                handshake_fraction = handshake_count / len(members)
                data_flow_fraction = data_flow_count / len(members)
                flags = Counter(flag for f in members for flag in f['flow_visibility_flags'])
                size = _size_observation(members,cfg)
                coherent_runs = _coherent_runs(starts, cfg)
                metrics['coherent_run_count'] = len(coherent_runs)
                metrics['coherent_runs'] = coherent_runs
                metrics.update(median_interval_ns=median_ns, mad_interval_ns=mad_ns,
                               relative_mad=(round(relative_mad,6) if relative_mad is not None else None),
                               bowley_skewness=dist['bowley_skewness'],
                               interval_min_ns=dist['min'], interval_max_ns=dist['max'],
                               intervals_in_band_fraction=round(fraction,6),
                               evaluated_interval_count=len(intervals),
                               observed_start_span_ns=observed_span_ns,
                               capture_coverage_fraction=round(observed_span_ns/span,6) if span > 0 else None,
                               observed_handshake_flow_count=handshake_count,
                               handshake_fraction=round(handshake_fraction,6),
                               data_bearing_flow_fraction=round(data_flow_fraction,6),
                               size_consistency=size,
                               visibility_flag_occurrences=dict(sorted(flags.items())))
                if observed_span_ns < cfg.min_observed_span_seconds*NS:
                    status = 'insufficient_data'; reasons.append('observation_span_too_short')
                elif median_ns < cfg.min_median_interval_seconds*NS:
                    status = 'not_detected'; reasons.append('burst_or_high_frequency_not_beacon_detector')
                elif flags.get('time_anomaly') or flags.get('truncated_or_partial'):
                    status = 'limited_visibility'; reasons.append('timestamps_or_payload_unreliable')
                elif handshake_fraction < cfg.min_handshake_fraction:
                    status = 'limited_visibility'; reasons.append('too_few_observed_tcp_handshakes')
                elif data_flow_fraction < cfg.min_data_flow_fraction:
                    status = 'not_detected'; reasons.append('repeated_empty_connection_attempts')
                elif relative_mad is None or relative_mad > cfg.max_relative_mad or fraction < cfg.min_intervals_in_band_fraction:
                    status = 'not_detected'; reasons.append('no_sustained_timing_regular_pattern')
                elif not coherent_runs:
                    status = 'not_detected'; reasons.append('no_contiguous_periodic_sequence')
                else:
                    status = 'detected'; reasons.append('sustained_interarrival_regularity')
                    # Link only starts within qualified runs, never the silent gaps.
                    accepted_starts = set()
                    start_cursor = 0  # Runs and starts are ordered; linear-time selection.
                    for run in coherent_runs:
                        while start_cursor < len(starts) and starts[start_cursor] < run['first_ns']:
                            start_cursor += 1
                        while start_cursor < len(starts) and starts[start_cursor] <= run['last_ns']:
                            accepted_starts.add(starts[start_cursor])
                            start_cursor += 1
                    supported_members = [m for m in members if m['first_seen_ns'] in accepted_starts]
                    primary_run = max(coherent_runs, key=lambda run:(
                        run['distinct_start_count'], run['last_ns'] - run['first_ns'],
                        -run['first_ns']))
                    primary_starts = [t for t in starts if primary_run['first_ns'] <= t <= primary_run['last_ns']]
                    primary_intervals = [b-a for a,b in zip(primary_starts,primary_starts[1:])]
                    primary_dist = _distribution(primary_intervals)
                    primary_median_ns = primary_dist['median']
                    primary_mad_ns = primary_dist['mad']
                    supported_size = _size_observation(supported_members,cfg)
                    metrics['qualifying_flow_count'] = len(supported_members)
                    metrics['qualifying_distinct_start_count'] = len(accepted_starts)
                    # This is not a separate alarm. Time is the primary claim.
                    support = ['interarrival_regularity','observed_connection_sequence']
                    if supported_size['origin']['consistent'] or supported_size['responder']['consistent']:
                        support.append('repeated_payload_size_consistency')
                    qualifying_active_ns = sum(run['last_ns']-run['first_ns'] for run in coherent_runs)
                    # Silence between distinct runs is not evidence of coverage.
                    if span > 0 and qualifying_active_ns / span >= 0.5:
                        support.append('observation_spans_half_capture')
                    finding_id = _id('FI-',capture['capture_id'],DETECTOR_ID,group_id)
                    evidence_ids = []
                    for etype in support:
                        eid = _id('EV-',finding_id,etype)
                        evidence_ids.append(eid)
                        emetrics = {
                            'interarrival_regularity': dict(median_interval_ns=primary_median_ns,
                                mad_interval_ns=primary_mad_ns,
                                relative_mad=round(primary_mad_ns/primary_median_ns,6),
                                bowley_skewness=primary_dist['bowley_skewness'],
                                intervals_in_band_fraction=round(_in_band_fraction(
                                    primary_intervals,primary_median_ns,cfg.relative_interval_tolerance),6),
                                interval_count=len(primary_intervals),
                                coherent_run_count=len(coherent_runs),coherent_runs=coherent_runs),
                            'observed_connection_sequence': dict(flow_count=len(supported_members),
                                observed_handshake_flow_count=sum(m['observed_tcp_state']=='observed_handshake' for m in supported_members),
                                first_connection_ns=min(run['first_ns'] for run in coherent_runs),
                                last_connection_ns=max(run['last_ns'] for run in coherent_runs),
                                excluded_outside_coherent_runs=len(members)-len(supported_members)),
                            'repeated_payload_size_consistency': supported_size,
                            'observation_spans_half_capture': dict(
                                observed_active_cadence_span_ns=qualifying_active_ns,
                                coherent_run_count=len(coherent_runs),capture_span_ns=span)
                        }[etype]
                        ev = dict(evidence_id=eid, finding_id=finding_id, evaluation_id=eval_id,
                                  type=etype, metrics=emetrics)
                        db.execute('INSERT INTO detector_evidence VALUES(?,?,?,?)',
                                   (eid,eval_id,etype,_json(ev)))
                        if len(evidence_preview)<max_json_findings*4:
                            evidence_preview.append(ev)
                    flow_ids=[f['flow_id'] for f in supported_members]
                    db.executemany('INSERT INTO detector_finding_flows VALUES(?,?)',
                                   ((finding_id, fid) for fid in flow_ids))
                    frames = _first_frames(db, flow_ids)
                    finding = dict(finding_id=finding_id,
                        detector_id=DETECTOR_ID, detector_version=DETECTOR_VERSION,
                        title='Periodic TCP connections',
                        type='periodic_communication',
                        subject=subject,
                        observed_first_ns=min(run['first_ns'] for run in coherent_runs),
                        observed_last_ns=max(run['last_ns'] for run in coherent_runs),
                        description=('Repeated TCP connection starts between the same endpoints '
                                     'show consistent interarrival timing.'),
                        interpretation='Observed regular TCP connection timing.',
                        primary_evidence_id=evidence_ids[0],
                        supporting_evidence_ids=evidence_ids[1:],
                        packet_frame_samples=frames,
                        packet_frame_samples_truncated=len(flow_ids)>len(frames),
                        complete_flow_provenance='detector_finding_flows -> flow_packets -> packets',
                        flow_count=len(flow_ids),
                        limitations=['Capture-local timing only; no historical baseline.',
                                     'No HTTP request-level or TLS SNI grouping.',
                                     'Payload size uses captured transport-layer bytes, not application content.',
                                     'Periodic legitimate software may produce the same behavior.'])
                    db.execute('INSERT INTO detector_findings VALUES(?,?,?)',
                               (finding_id,eval_id,_json(finding)))
                    if len(finding_preview)<max_json_findings:
                        finding_preview.append(finding)
                    counters['finding_count'] += 1
            db.execute('INSERT INTO detector_evaluations VALUES(?,?,?,?,?)',
                       (eval_id,group_id,status,_json(reasons),_json(metrics)))
            counters[status]+=1
            if status!='detected' and len(evaluation_preview)<max_json_evaluations:
                evaluation_preview.append(dict(evaluation_id=eval_id,group_id=group_id,
                                               subject=subject,status=status,reasons=reasons))
        db.commit()
        return dict(detector_id=DETECTOR_ID, version=DETECTOR_VERSION,
                    reference='Capture-local TCP connection timing measurements',
                    evaluation_scope='TCP IP-port communication groups, capture-local',
                    run_parameters=asdict(cfg), summary=dict(sorted(counters.items())),
                    findings=finding_preview, evidence=evidence_preview,
                    nonfinding_evaluations_preview=evaluation_preview,
                    findings_preview_truncated=counters['finding_count']>max_json_findings,
                    full_provenance_index=str(index_path),
                    no_threat_scores_exposed=True)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
