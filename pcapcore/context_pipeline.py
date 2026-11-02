"""Observational context layer; finding and case evidence remains unchanged."""
from __future__ import annotations
from pathlib import Path
from .episode_pipeline import analyze_with_episodes
from .host_dns_context import attach_host_dns_context


def analyze_with_context(path: str | Path, index_path: str | Path, *,
                         max_context_hosts: int = 20, max_context_dns: int = 20,
                         **kwargs) -> dict:
    report=analyze_with_episodes(path,index_path,**kwargs)
    result=attach_host_dns_context(index_path,report['capture'],
                                   max_json_hosts=max_context_hosts,
                                   max_json_dns=max_context_dns)
    report['engine_version']='0.11.0-host-dns-context'
    report['stage']='observations_features_detectors_cases_episodes_host_dns_context'
    report['host_dns_context']=result
    report['analyst_view']='independent host/DNS context > unmodified episodes/cases/findings'
    return report
