"""Conservative correlation without changing detector outputs."""
from __future__ import annotations
from pathlib import Path
from .traffic_pipeline import analyze_with_traffic
from .correlation import correlate_findings


def analyze_with_correlation(path: str | Path, index_path: str | Path, *,
                             max_cases: int=25, **kwargs) -> dict:
    report=analyze_with_traffic(path,index_path,**kwargs)
    result=correlate_findings(index_path,report['capture'],max_json_cases=max_cases)
    report['engine_version']='0.7.0-correlation'
    report['stage']='observations_features_detectors_and_evidence_based_case_correlation'
    report['correlation']=result
    report['cases']=result['cases']
    report['cases_preview_truncated']=result['cases_preview_truncated']
    report['analyst_view']='cases; raw detector findings retained for audit'
    return report
