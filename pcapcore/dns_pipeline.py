"""Add DNS observations without altering prior observations."""
from __future__ import annotations
from pathlib import Path
from .scan_pipeline import analyze_with_scanning
from .dns_behavior import analyze_dns_behavior, DNSParameters


def analyze_with_dns(path: str | Path, index_path: str | Path, *,
                     dns_parameters: DNSParameters | None = None,
                     max_findings: int = 25, max_evaluations: int = 25, **kwargs) -> dict:
    report=analyze_with_scanning(path,index_path,max_findings=max_findings,
                                 max_evaluations=max_evaluations,**kwargs)
    det=analyze_dns_behavior(index_path,report['capture'],parameters=dns_parameters,
                             max_json_findings=max_findings,max_json_evaluations=max_evaluations)
    report['engine_version']='0.5.0-dns'
    report['stage']='observation_features_periodicity_scans_dns'
    report['detectors_status']='periodicity_tcp_scan_and_dns_nxdomain_experimental'
    report['detector_evaluations'].append(dict(detector_id=det['detector_id'],version=det['version'],
               status='completed',summary=det['summary'],full_records_index='detector_evaluations'))
    report['findings'].extend(det['findings']);report['evidence'].extend(det['evidence'])
    report['dns_detection']={k:v for k,v in det.items() if k not in ('findings','evidence')}
    report['findings_preview_truncated']|=det['findings_preview_truncated']
    return report
