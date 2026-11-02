"""Add a behavioral timing detector without modifying packet observations."""
from __future__ import annotations
from pathlib import Path
from .pipeline import analyze_with_features
from .beaconing import analyze_periodic_communications, BeaconParameters


def analyze_with_beaconing(path: str | Path, index_path: str | Path, *,
                           max_feature_groups: int = 20, max_feature_windows: int = 20,
                           max_feature_hosts: int = 20,
                           feature_windows_sec: tuple[int, ...] = (60,300),
                           max_findings: int = 25,
                           max_evaluations: int = 25,
                           beacon_parameters: BeaconParameters | None = None,
                           **kwargs) -> dict:
    report = analyze_with_features(path, index_path,
                                   max_feature_groups=max_feature_groups,
                                   max_feature_windows=max_feature_windows,
                                   max_feature_hosts=max_feature_hosts,
                                   feature_windows_sec=feature_windows_sec, **kwargs)
    det = analyze_periodic_communications(index_path, report['capture'],
                                          parameters=beacon_parameters,
                                          max_json_findings=max_findings,
                                          max_json_evaluations=max_evaluations)
    report['engine_version'] = '0.3.0-beaconing'
    report['stage'] = 'observation_features_and_periodic_tcp_detection'
    report['detectors_status'] = 'periodic_tcp_communication_enabled_only'
    report['detector_evaluations'] = [
        dict(detector_id=det['detector_id'], version=det['version'],
             status='completed', summary=det['summary'],
             full_records_index='detector_evaluations')]
    report['findings'] = det['findings']
    report['evidence'] = det['evidence']
    report['detection'] = {k:v for k,v in det.items() if k not in ('findings','evidence')}
    report['findings_preview_truncated'] = det['findings_preview_truncated']
    return report
