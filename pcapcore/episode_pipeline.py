"""Presentation-only association of related observation episodes."""
from __future__ import annotations
from pathlib import Path
from .correlation_pipeline import analyze_with_correlation
from .episodes import associate_scan_episodes


def analyze_with_episodes(path: str | Path, index_path: str | Path, *,
                          max_episodes: int = 20, **kwargs) -> dict:
    report = analyze_with_correlation(path, index_path, **kwargs)
    episodes = associate_scan_episodes(index_path, report['capture'],
                                       max_json_episodes=max_episodes)
    report['engine_version'] = '0.10.0-episode-presentation'
    report['stage'] = 'observations_features_detectors_cases_and_presentation_episodes'
    report['case_episodes'] = episodes
    report['episodes'] = episodes['episodes']
    report['episodes_preview_truncated'] = episodes['episodes_preview_truncated']
    report['analyst_view'] = 'episodes (optional) > unchanged cases > unchanged raw detector findings'
    return report
