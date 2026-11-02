"""Add traffic observations to the analysis report."""
from __future__ import annotations
from pathlib import Path
from .dns_pipeline import analyze_with_dns
from .traffic_behavior import analyze_traffic_behavior, TrafficParameters


def analyze_with_traffic(path: str | Path, index_path: str | Path, *,
                         traffic_parameters: TrafficParameters | None = None,
                         max_findings: int = 25, max_evaluations: int = 25, **kwargs) -> dict:
    report=analyze_with_dns(path,index_path,max_findings=max_findings,
                            max_evaluations=max_evaluations,**kwargs)
    det=analyze_traffic_behavior(index_path,report['capture'],parameters=traffic_parameters,
                                 max_json_findings=max_findings,max_json_evaluations=max_evaluations)
    report['engine_version']='0.6.0-traffic'
    report['stage']='observation_features_periodicity_scans_dns_traffic'
    report['detectors_status']='periodicity_scans_dns_and_traffic_observations_enabled'
    report['detector_evaluations'].append(dict(detector_id=det['detector_id'],version=det['version'],
               status='completed',summary=det['summary'],full_records_index='detector_evaluations'))
    report['findings'].extend(det['findings']);report['evidence'].extend(det['evidence'])
    report['traffic_detection']={k:v for k,v in det.items() if k not in ('findings','evidence')}
    report['findings_preview_truncated']|=det['findings_preview_truncated']
    return report
