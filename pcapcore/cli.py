"""CLI for the observation + feature extraction PCAP core."""
from __future__ import annotations
import argparse
import json
import sys
import tempfile
from pathlib import Path
from .engine import analyze
from .pipeline import analyze_with_features
from .detection_pipeline import analyze_with_beaconing
from .scan_pipeline import analyze_with_scanning
from .dns_pipeline import analyze_with_dns
from .traffic_pipeline import analyze_with_traffic
from .correlation_pipeline import analyze_with_correlation
from .episode_pipeline import analyze_with_episodes
from .context_pipeline import analyze_with_context
from .reader import PcapFormatError
from .report_html import write_html_report
from .ftp_control import collect_ftp_control
from .artifacts import ArtifactTransaction, normalize_index_references


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Offline PCAP behavioral observations, DNS, traffic and evidence correlation')
    ap.add_argument('pcap', type=Path, help='Input classic .pcap, never modified')
    ap.add_argument('-o', '--output', type=Path, help='JSON output (default <pcap>.observations.json)')
    ap.add_argument('--index', type=Path, help='SQLite path when --keep-index is explicitly set')
    ap.add_argument('--keep-index', action='store_true', help='Development/debug opt-in: retain SQLite after analysis')
    ap.add_argument('--no-html', action='store_true', help='Disable default HTML output (not recommended for analyst workflow)')
    ap.add_argument('--traffic-table-limit', type=int, default=1000, help='Maximum embedded rows in each traffic table, 1..1000')
    ap.add_argument('--html', type=Path, help='Optional offline HTML report (full pipeline only)')
    ap.add_argument('--max-html-cases', type=int, default=None, help='Optional explicit finding-card limit (default: ALL findings)')
    ap.add_argument('--local-cidr', action='append', default=[], help='Configured local network CIDR; repeatable')
    ap.add_argument('--max-flows', type=int, default=200, help='Maximum JSON flow/host previews; complete flow data remains in temporary SQLite during analysis')
    ap.add_argument('--max-events', type=int, default=100, help='Maximum JSON DNS/ARP/ICMP event previews')
    ap.add_argument('--udp-idle', type=float, default=60, help='UDP pseudo-flow inactivity timeout seconds')
    ap.add_argument('--tcp-idle', type=float, default=1800, help='TCP 5-tuple heuristic inactivity timeout seconds')
    ap.add_argument('--no-features', action='store_true', help='Disable feature extraction and detectors')
    ap.add_argument('--max-feature-groups', type=int, default=20, help='Feature-group JSON preview limit; full SQLite remains')
    ap.add_argument('--max-feature-windows', type=int, default=20, help='Window JSON preview limit; full SQLite remains')
    ap.add_argument('--max-feature-hosts', type=int, default=20, help='Host/DNS/ARP/ICMP JSON preview limit')
    ap.add_argument('--no-scans', action='store_true', help='Disable scan, DNS and traffic detectors')
    ap.add_argument('--no-dns', action='store_true', help='Disable DNS and traffic detectors')
    ap.add_argument('--no-traffic', action='store_true', help='Disable traffic and correlation stages')
    ap.add_argument('--no-correlation', action='store_true', help='Disable case correlation and later stages')
    ap.add_argument('--max-cases', type=int, default=25, help='Maximum analyst case JSON previews; HTML contains all cases')
    ap.add_argument('--max-episodes', type=int, default=20, help='Maximum parent episode JSON previews')
    ap.add_argument('--no-episodes', action='store_true', help='Disable episode association')
    ap.add_argument('--no-context', action='store_true', help='Disable host and DNS context enrichment')
    ap.add_argument('--max-context-hosts', type=int, default=20, help='Maximum host context JSON previews')
    ap.add_argument('--max-context-dns', type=int, default=20, help='Maximum DNS context JSON previews')
    ap.add_argument('--no-detections', action='store_true', help='Disable all behavior detectors')
    ap.add_argument('--max-findings', type=int, default=25, help='Maximum JSON finding previews; HTML contains all cases')
    ap.add_argument('--overwrite', action='store_true', help='Explicitly replace existing JSON/HTML artifacts')
    args = ap.parse_args(argv)
    output = args.output or args.pcap.with_name(args.pcap.name + '.observations.json')
    index = args.index or output.with_name(output.name + '.sqlite')
    can_render_html = not any((args.no_features, args.no_detections, args.no_scans,
                              args.no_dns, args.no_traffic, args.no_correlation))
    if args.no_html and args.html is not None:
        ap.error('--html and --no-html are mutually exclusive')
    if args.no_html and not args.keep_index and can_render_html:
        ap.error('--no-html on a full analysis requires --keep-index to avoid losing the only complete evidence index')
    html = None if args.no_html or not can_render_html else (args.html or output.with_suffix('.html'))
    if args.html is not None and not can_render_html:
        ap.error('--html requires the full correlation pipeline')
    if args.index is not None and not args.keep_index:
        ap.error('--index requires --keep-index; otherwise SQLite is temporary')
    if not 1 <= args.traffic_table_limit <= 1000:
        ap.error('--traffic-table-limit must be in the range 1..1000')
    if len({args.pcap.resolve(), output.resolve(), index.resolve()}) != 3:
        ap.error('Input PCAP, JSON output and SQLite path must be different')
    if any(x < 0 for x in (args.max_flows, args.max_events, args.max_feature_groups,
                            args.max_feature_windows, args.max_feature_hosts, args.max_findings,
                            args.max_cases, args.max_episodes, args.max_context_hosts, args.max_context_dns)):
        ap.error('Preview limits must be non-negative')
    if args.max_html_cases is not None and args.max_html_cases < 0:
        ap.error('--max-html-cases must be non-negative')
    if html is not None and len({args.pcap.resolve(),output.resolve(),index.resolve(),html.resolve()}) != 4:
        ap.error('HTML, JSON, SQLite and input PCAP paths must all differ')
    targets = [output] + ([html] if html is not None else []) + ([index] if args.keep_index else [])
    if not args.overwrite and any(x.exists() or x.is_symlink() for x in targets):
        ap.error('Output/HTML/index exists; choose new paths or pass --overwrite')
    if not args.keep_index and index.exists():
        # Do not delete an index created by an older release: it is user data.
        print(f'NOTE: Previous SQLite file left untouched: {index}',file=sys.stderr)
    output.parent.mkdir(parents=True,exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix='.pcapcore-run-', dir=output.parent) as tmp:
            with ArtifactTransaction(targets, overwrite=args.overwrite) as artifacts:
                work_index = artifacts.staged(index) if args.keep_index else Path(tmp) / 'work.sqlite'
                # Work only on a new index, leaving existing reports intact on failure.
                common = dict(max_flows=args.max_flows, max_events=args.max_events,
                              local_cidrs=args.local_cidr, udp_idle_sec=args.udp_idle,
                              tcp_idle_sec=args.tcp_idle, overwrite=False)
                if args.no_features:
                    report = analyze(args.pcap, work_index, **common)
                elif args.no_detections:
                    report = analyze_with_features(
                        args.pcap, work_index, max_feature_groups=args.max_feature_groups,
                        max_feature_windows=args.max_feature_windows,
                        max_feature_hosts=args.max_feature_hosts, **common)
                elif args.no_scans:
                    report = analyze_with_beaconing(
                        args.pcap, work_index, max_feature_groups=args.max_feature_groups,
                        max_feature_windows=args.max_feature_windows,
                        max_feature_hosts=args.max_feature_hosts,
                        max_findings=args.max_findings, **common)
                else:
                    runner = (analyze_with_scanning if args.no_dns else
                              analyze_with_dns if args.no_traffic else
                              analyze_with_traffic if args.no_correlation else
                              analyze_with_correlation if args.no_episodes else
                              analyze_with_episodes if args.no_context else
                              analyze_with_context)
                    opt = {} if (args.no_dns or args.no_traffic or args.no_correlation) else {'max_cases': args.max_cases}
                    if runner in (analyze_with_episodes,analyze_with_context): opt['max_episodes'] = args.max_episodes
                    if runner is analyze_with_context:
                        opt.update(max_context_hosts=args.max_context_hosts, max_context_dns=args.max_context_dns)
                    report = runner(
                        args.pcap, work_index, max_feature_groups=args.max_feature_groups,
                        max_feature_windows=args.max_feature_windows,
                        max_feature_hosts=args.max_feature_hosts,
                        max_findings=args.max_findings, **opt, **common)
                if can_render_html and not (args.no_episodes or args.no_context):
                    report['engine_version'] = '0.24.0'
                    report['stage'] = 'observations_features_detectors_cases_and_evidence'
                    report['analyst_view'] = 'flat_evidence_first_findings'
                if can_render_html and not (args.no_episodes or args.no_context):
                    report['protocol_observations'] = {
                        'ftp_control': collect_ftp_control(args.pcap, work_index)
                    }
                if args.keep_index:
                    normalize_index_references(report, work_index, index)
                    report['index_retention'] = 'explicitly_retained'
                else:
                    def _remove_transient_paths(value):
                        if isinstance(value, dict):
                            for key, val in value.items():
                                if key in ('full_provenance_index','full_index') and isinstance(val,str):
                                    value[key] = None
                                else:
                                    _remove_transient_paths(val)
                        elif isinstance(value,list):
                            for item in value:
                                _remove_transient_paths(item)
                    _remove_transient_paths(report)
                    report['index_retention'] = ('temporary_removed_after_successful_report' if html is not None else 'temporary_removed_after_analysis')

                with artifacts.staged(output).open('w', encoding='utf-8') as fh:
                    json.dump(report, fh, ensure_ascii=False, sort_keys=True, indent=2)
                    fh.write('\n')
                if html is not None:
                    write_html_report(report, work_index, artifacts.staged(html),
                                      max_cases=args.max_html_cases, table_limit=args.traffic_table_limit, overwrite=False)
                artifacts.commit()
    except (OSError, PcapFormatError, ValueError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2
    s = report['summary']
    print(f"Observed {report['capture']['packet_count']} frames, {s['flow_count']} flows, "
          f"{s['dns_transaction_count']} DNS transactions; "
          f"{len(report.get('findings',[]))} finding previews, detector status: {report.get('detectors_status','disabled')}.")
    print(f'JSON: {output}')
    if html is not None: print(f'Offline HTML: {html}')
    print(f'SQLite: {index}' if args.keep_index else 'Temporary SQLite removed after report generation')
    return 0
