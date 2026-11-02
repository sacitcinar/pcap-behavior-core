"""Add TCP scanning observations without rewriting detector rows."""
from __future__ import annotations
from pathlib import Path
from .detection_pipeline import analyze_with_beaconing
from .scanning import analyze_scan_patterns, ScanParameters


def analyze_with_scanning(path: str | Path, index_path: str | Path, *,
                          scan_parameters: ScanParameters | None = None,
                          max_findings: int = 25,
                          max_evaluations: int = 25,
                          **kwargs) -> dict:
    # Include all prior stages unchanged, then append scanning rows.
    report=analyze_with_beaconing(path,index_path,max_findings=max_findings,
                                 max_evaluations=max_evaluations,**kwargs)
    result=analyze_scan_patterns(index_path,report['capture'],
                                 parameters=scan_parameters,
                                 max_json_findings=max_findings,
                                 max_json_evaluations=max_evaluations)
    report['engine_version']='0.4.0-scanning'
    report['stage']='observation_features_periodicity_and_tcp_scan_patterns'
    report['detectors_status']='periodic_tcp_communication_and_tcp_scan_patterns_enabled'
    report['detector_evaluations'].append(dict(
        detector_id=result['detector_id'],version=result['version'],
        status='completed',summary=result['summary'],
        full_records_index='detector_evaluations'))
    report['findings'].extend(result['findings'])
    report['evidence'].extend(result['evidence'])
    report['scan_detection']={k:v for k,v in result.items() if k not in ('findings','evidence')}
    report['findings_preview_truncated']=(report['findings_preview_truncated']
                                          or result['findings_preview_truncated'])
    return report
