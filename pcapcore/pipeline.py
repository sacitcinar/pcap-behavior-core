"""Feature extraction pipeline preserving the packet observation contract."""
from __future__ import annotations
from pathlib import Path
from .engine import analyze
from .features import extract_features, FEATURE_VERSION


def analyze_with_features(path: str | Path, index_path: str | Path, *,
                          max_feature_groups: int = 20, max_feature_windows: int = 20,
                          max_feature_hosts: int = 20,
                          feature_windows_sec: tuple[int, ...] = (60, 300), **kwargs) -> dict:
    base = analyze(path, index_path, **kwargs)
    features = extract_features(
        index_path, base['capture'], local_cidrs=kwargs.get('local_cidrs'),
        windows_sec=feature_windows_sec,
        max_json_groups=max_feature_groups,
        max_json_windows=max_feature_windows,
        max_json_hosts=max_feature_hosts,
    )
    # Stage-only schema extension; base capture/summary/flows/events are unchanged.
    base['engine_version'] = FEATURE_VERSION
    base['stage'] = 'observation_and_feature_extraction_no_detectors'
    base['feature_extraction'] = features
    return base
