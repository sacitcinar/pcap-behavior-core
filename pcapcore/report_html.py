"""One-file, offline analyst report; no SQL is needed after rendering.

All traffic is analyzed. Only general-purpose traffic tables are bounded;
all findings/cases are rendered by default. HTML is independent of SQLite.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from pathlib import Path
import base64
import json
import sqlite3
from .dashboard_data import collect_dashboard, TABLE_LIMIT, _ip_sort

_EN_MONTHS = ('January','February','March','April','May','June','July','August','September','October','November','December')

def _h(value):
    return escape(str(value), quote=True)

def _capture_datetime_parts(ns):
    if ns is None:
        return 'Unknown', None
    dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
    return f'{dt.day} {_EN_MONTHS[dt.month-1]} {dt.year}, {dt:%H:%M:%S}', dt.isoformat(timespec='seconds')

def _capture_time_html(ns):
    s, iso = _capture_datetime_parts(ns)
    return ('<time datetime="'+_h(iso)+'">'+_h(s)+'</time>') if iso else '<span>Unknown</span>'

def _utc(ns):
    if ns is None:
        return '—'
    return datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc).strftime('%d %b %Y, %H:%M:%S UTC')

def _n(v):
    return f'{int(v or 0):,}'

def _size(n):
    val = float(n or 0)
    for suffix in ('B','KiB','MiB','GiB','TiB'):
        if val < 1024 or suffix == 'TiB':
            return f'{val:,.1f} {suffix}' if suffix != 'B' else f'{int(val):,} B'
        val /= 1024

_LABELS = {
    'vertical_port_scan_pattern': 'TCP destination port sweep',
    'horizontal_port_scan_pattern': 'TCP multiple-host probe sweep',
    'mixed_port_scan_pattern': 'TCP multi-axis probe sweep',
    'periodic_communication': 'Periodic TCP connections',
    'concentrated_nxdomain_diversity': 'NXDOMAIN diversity',
    'long_lived_tcp_flow_observed': 'Long-lived TCP flow',
    'large_outbound_payload_observed': 'Outbound payload volume',
}

def _type_label(t):
    return _LABELS.get(t, str(t).replace('_',' '))

# Static assets, SHA-256 CSP. No external dependency, fetch/XHR or CDN.
_UI_JS = r"""
(() => {
  'use strict';
  const sections = Array.from(document.querySelectorAll('.report-section'));
  const links = Array.from(document.querySelectorAll('.side-link'));
  const app = document.getElementById('app');
  const sidebar = document.getElementById('sidebar');
  document.documentElement.classList.add('js-ready');
  function navigate() {
    const hashTarget=decodeURIComponent(location.hash.slice(1));
    const requested=hashTarget.startsWith('case-') ? 'cases' : hashTarget;
    const selected = sections.some(x => x.id === requested) ? requested : 'overview';
    sections.forEach(s => { s.hidden = s.id !== selected; });
    links.forEach(l => { const active = l.getAttribute('href') === '#' + selected;
      l.classList.toggle('active', active);
      if (active) l.setAttribute('aria-current','page'); else l.removeAttribute('aria-current'); });
    const title = document.getElementById('current-section');
    const activeLink = links.find(l => l.getAttribute('href') === '#' + selected);
    if (title && activeLink) title.textContent = activeLink.dataset.title || activeLink.textContent;
    if (app && window.innerWidth < 810) app.classList.remove('mobile-open');
    if (location.hash.startsWith('#case-')) {
      const el = document.getElementById(location.hash.slice(1));
      if (el) { const parent=document.getElementById('finding-details'); if(parent) parent.open=true; el.hidden=false; el.open = true; setTimeout(() => el.scrollIntoView({block:'start'}), 0); }
    } else { setTimeout(() => window.scrollTo(0,0), 0); }
  }
  window.addEventListener('hashchange', navigate);
  document.getElementById('sidebar-toggle')?.addEventListener('click',() => app.classList.toggle('collapsed'));
  document.getElementById('mobile-menu')?.addEventListener('click',() => app.classList.toggle('mobile-open'));
  navigate();

  // Search/sort/page ONLY the rows embedded in this HTML, never the entire PCAP.
  for (const frame of document.querySelectorAll('[data-table]')) {
    const body = frame.querySelector('tbody');
    if (!body) continue;
    const rows = Array.from(body.querySelectorAll('tr'));
    const search = frame.querySelector('[data-table-search]');
    const pageSize = frame.querySelector('[data-page-size]');
    const count = frame.querySelector('[data-table-count]');
    const current = frame.querySelector('[data-page-current]');
    const prev = frame.querySelector('[data-page-prev]');
    const next = frame.querySelector('[data-page-next]');
    const csv = frame.querySelector('[data-table-csv]');
    let page=0, sortIndex=-1, ascending=false;
    const originalPosition=new Map(rows.map((r,i)=>[r,i]));
    const collation = new Intl.Collator('en',{numeric:true,sensitivity:'base'});
    const filtered = () => {
      const q=(search?.value || '').trim().toLocaleLowerCase('en');
      const matched = rows.filter(r => !q || (r.dataset.search||r.textContent).toLocaleLowerCase('en').includes(q));
      if (sortIndex >= 0) {
        const type = frame.querySelectorAll('th')[sortIndex]?.dataset.type || 'text';
        matched.sort((a,b) => {
          const av=a.cells[sortIndex]?.dataset.sort ?? a.cells[sortIndex]?.textContent ?? '';
          const bv=b.cells[sortIndex]?.dataset.sort ?? b.cells[sortIndex]?.textContent ?? '';
          const cmp=type === 'time' ? (BigInt(av)<BigInt(bv)?-1:(BigInt(av)>BigInt(bv)?1:0))
                    : type === 'number' ? Number(av)-Number(bv)
                    : type === 'ip' ? (av < bv ? -1 : (av > bv ? 1 : 0)) : collation.compare(av,bv);
          return (ascending ? cmp : -cmp) || originalPosition.get(a)-originalPosition.get(b);
        });
      }
      return matched;
    };
    function render() {
      const selected=filtered();
      const size=Number(pageSize?.value || 25);
      page=Math.min(page,Math.max(0,Math.ceil(selected.length/size)-1));
      const selectedPage=new Set(selected.slice(page*size,(page+1)*size));
      rows.forEach(row => { row.hidden = !selectedPage.has(row); });
      // Sorting the DOM is unnecessary; move only visible items into selected order.
      selected.filter(r=>selectedPage.has(r)).forEach(r=>body.appendChild(r));
      if (count) count.textContent=`${selected.length} matching / ${rows.length} in report / ${frame.dataset.total} total`;
      if (current) current.textContent=`${selected.length ? page+1 : 0} / ${Math.ceil(selected.length/size) || 0}`;
      if (prev) prev.disabled=page===0;
      if (next) next.disabled=(page+1)*size >= selected.length;
    }
    search?.addEventListener('input',()=>{page=0;render();});
    pageSize?.addEventListener('change',()=>{page=0;render();});
    prev?.addEventListener('click',()=>{page=Math.max(0,page-1);render();});
    next?.addEventListener('click',()=>{page++;render();});
    csv?.addEventListener('click', () => {
      // Export only rows embedded in the HTML, after any local filtering/sorting.
      // Escape spreadsheet formulas in attacker-controlled names and addresses.
      const guard = value => {
        let text = String(value ?? '');
        if (/^\s*[=+\-@\t\r]/.test(text)) text="'"+text;
        return '"'+text.replace(/"/g,'""')+'"';
      };
      const headers = Array.from(frame.querySelectorAll('th')).map(h => h.textContent.trim());
      const lines = [headers.map(guard).join(',')];
      filtered().forEach(row => lines.push(Array.from(row.cells).map(c=>guard(c.textContent.trim())).join(',')));
      const blob = new Blob(['\ufeff',lines.join('\r\n')],{type:'text/csv;charset=utf-8'});
      const uri = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href=uri; a.download='pcap-'+(frame.dataset.table || 'table')+'.csv';
      a.click();
      setTimeout(()=>URL.revokeObjectURL(uri),1000);
    });
    frame.querySelectorAll('th .sort-trigger').forEach((button,i)=>button.addEventListener('click',()=>{
      if (sortIndex===i) ascending=!ascending; else {sortIndex=i;ascending=false;}
      frame.querySelectorAll('th').forEach((th,j)=>th.setAttribute('aria-sort',j===i?(ascending?'ascending':'descending'):'none'));
      page=0;render();
    }));
    render();
  }
})();
""".strip()

_UI_CSS = r"""
:root{color-scheme:dark;--bg:#0e1420;--panel:#182234;--panel2:#1e2a3e;--sidebar:#101929;--line:#304057;--text:#ecf2fb;--sub:#a7b7cb;--soft:#24354e;--accent:#7da9ff;--highlight:#31466a;--good:#7ec9b2}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,Segoe UI,Arial,sans-serif}h1,h2,h3,p{margin-top:0}h1{font-size:26px;letter-spacing:-.04em}h2{font-size:22px;letter-spacing:-.03em}h3{font-size:16px}a{color:var(--accent)}a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:3px}.muted,.extra{color:var(--sub)}.extra{font-size:12px}.eyebrow,.k{font-size:11px;letter-spacing:.09em;text-transform:uppercase;color:var(--sub);font-weight:700}.app{display:grid;grid-template-columns:244px minmax(0,1fr);min-height:100vh;transition:grid-template-columns .2s}.app.collapsed{grid-template-columns:70px minmax(0,1fr)}.sidebar{height:100vh;position:sticky;top:0;background:var(--sidebar);border-right:1px solid var(--line);padding:24px 12px;overflow-y:auto}.brand{display:flex;gap:11px;align-items:center;margin:2px 9px 28px;font-weight:800;font-size:15px;white-space:nowrap}.brand-logo{background:linear-gradient(145deg,#3867b4,#28416a);border:1px solid #7098d5;border-radius:10px;display:grid;place-items:center;width:34px;height:34px;flex:none}.nav-caption{color:#8295af;font-size:10px;font-weight:750;letter-spacing:.13em;margin:20px 11px 7px;white-space:nowrap}.side-link{padding:11px 12px;display:flex;gap:12px;align-items:center;color:#b6c6da;text-decoration:none;border-radius:8px;margin:3px 0;font-size:13px;white-space:nowrap}.side-link:hover{background:#ffffff0d;color:#fff}.side-link.active{background:var(--highlight);color:#f5faff;border-left:3px solid #8eb7ff;padding-left:9px;font-weight:700}.side-icon{width:20px;display:inline-flex;justify-content:center;font-size:17px;flex:none}.collapsed .brand-text,.collapsed .nav-caption,.collapsed .side-text{display:none}.app-main{min-width:0}.topbar{border-bottom:1px solid var(--line);padding:17px 36px;display:flex;justify-content:space-between;align-items:center;gap:12px;position:sticky;top:0;background:#101a2bfa;z-index:3}.topbar-title{font-size:14px;font-weight:750}.topbar-meta{color:var(--sub);font-size:12px}.top-actions{display:flex;align-items:center;gap:13px}.shell{max-width:1480px;padding:30px 36px 90px;margin:0 auto}.report-section{scroll-margin-top:88px}.case-item{scroll-margin-top:90px}.report-section[hidden],.case-item[hidden],tbody tr[hidden]{display:none!important}.section-head{display:flex;align-items:end;justify-content:space-between;gap:14px;margin-bottom:18px;flex-wrap:wrap}.section-head p{color:var(--sub);font-size:13px;margin:2px 0 0}.panel{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:20px;margin:13px 0}.hero{background:linear-gradient(120deg,#1a2c49,#1b273c 60%,#172337);border:1px solid #3b4c68;border-radius:14px;padding:25px}.capture-clock{margin-top:17px;background:#0c17283f;padding:15px;border:1px solid #53688280;border-radius:10px}.clock-range{display:flex;flex-wrap:wrap;gap:12px;align-items:center;font-size:16px;font-weight:650;letter-spacing:-.02em}.clock-note{font-size:12px;color:var(--sub);margin-top:4px}.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:17px 0}.metric{background:var(--panel);border:1px solid var(--line);padding:20px;border-radius:12px}.metric .value{font-size:26px;line-height:1.2;font-weight:800;letter-spacing:-.045em;overflow-wrap:anywhere}.metric .label{font-size:12px;color:var(--sub);margin-bottom:7px}.notice{background:#1c2d46;border-left:3px solid var(--accent);padding:13px 16px;border-radius:6px;font-size:13px;margin:13px 0}.bars{display:grid;gap:14px}.bar-row{display:grid;grid-template-columns:210px 1fr 60px;gap:14px;align-items:center}.track{background:#2b3950;height:12px;border-radius:99px;overflow:hidden}.fill{height:100%;border-radius:99px;background:linear-gradient(90deg,#4a78cf,#83b8ff)}.count{text-align:right;font-weight:650}.controls{display:flex;flex-wrap:wrap;gap:12px;align-items:end}.field{flex:1;min-width:190px}.field label{font-size:12px;color:var(--sub);display:block;margin-bottom:5px}input,select,button{font:inherit;color:var(--text);background:#121d2f;border:1px solid #3c4f67;border-radius:8px;padding:9px 12px}input{width:100%}input::placeholder{color:#889bb3}button{cursor:pointer}button:hover{background:#253751}button:disabled{opacity:.38;cursor:default}.small-button{padding:7px 10px;font-size:12px}.csv-button{display:none}.js-ready .csv-button{display:inline-block}.ghost{background:transparent}.table-panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:14px 0;overflow:hidden}.table-toolbar{padding:17px 19px;display:flex;gap:16px;flex-wrap:wrap;align-items:center;justify-content:space-between}.table-toolbar input{max-width:310px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:12px;min-width:700px}th,td{padding:12px 13px;text-align:left;border-bottom:1px solid #304057}th{background:#1f3046;color:#bfcde2;font-size:11px;letter-spacing:.025em;white-space:nowrap}td{font-variant-numeric:tabular-nums}td.number{text-align:right}tr:hover td{background:#ffffff08}th .sort-trigger{background:none;border:0;color:inherit;padding:0;font-size:inherit;letter-spacing:inherit;font-weight:700;cursor:pointer}th .sort-trigger:after{content:' ↕';color:#8099b7}th[aria-sort=ascending] .sort-trigger:after{content:' ↑';color:#b1ceff}th[aria-sort=descending] .sort-trigger:after{content:' ↓';color:#b1ceff}.table-footer{padding:13px 17px;display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;color:var(--sub);font-size:12px}.pager{display:flex;gap:7px;align-items:center}.pager select{padding:5px 7px;font-size:12px}.table-note{font-size:12px;color:var(--sub);margin:0 18px 16px}.tag{border-radius:99px;background:#263953;color:#cbdcf9;padding:3px 9px;font-size:11px;display:inline-block}.case-item{margin:10px 0;border-radius:11px;border:1px solid var(--line);background:var(--panel)}.case-item summary{cursor:pointer;padding:15px 17px;display:flex;gap:10px;align-items:start}.case-item summary:before{content:'+';border:1px solid var(--line);border-radius:5px;width:24px;text-align:center;font-size:18px;line-height:22px;flex:none}.case-item[open]>summary:before{content:'−'}.case-title{font-weight:700}.case-sub{color:var(--sub);font-size:12px;display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-top:7px}.case-body{border-top:1px solid var(--line);padding:17px}.case-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.v{font-size:13px;overflow-wrap:anywhere}.nested{border:1px solid var(--line);border-radius:10px;padding:12px;margin:10px 0}.nested>summary{cursor:pointer;font-weight:650}.detail-list{padding-left:23px}.timeline{height:185px;display:flex;align-items:end;gap:3px;margin-top:20px;border-bottom:1px solid #465573;padding:10px 2px 0}.timeline .bin{flex:1;min-width:2px;border-radius:3px 3px 0 0;background:linear-gradient(#7caeff,#3c6bbd)}.timeline-labels{display:flex;justify-content:space-between;color:var(--sub);font-size:12px;margin:8px 0}.context-item{border-bottom:1px solid var(--line);padding:10px 0}.context-item summary{cursor:pointer}code{word-break:break-all;font-size:12px}.evidence-json{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;color:#c5d6ef}.footer{margin:28px 0;color:var(--sub);font-size:12px}.mobile-only{display:none}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:1100px){.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.shell{padding:24px 22px 70px}.topbar{padding:14px 22px}}
@media(max-width:810px){.app{display:block}.sidebar{position:fixed;left:0;top:0;width:245px;z-index:8;transform:translateX(-100%);transition:transform .2s}.app.mobile-open .sidebar{transform:translateX(0)}.mobile-only{display:inline-block}.topbar{padding:13px 17px}.shell{padding:17px 14px 45px}.bar-row{grid-template-columns:115px 1fr 40px;gap:8px;font-size:12px}.metric .value{font-size:22px}.table-toolbar input{max-width:100%}}
@media print{.sidebar,.top-actions,.table-toolbar input,.pager,.controls{display:none!important}.app{display:block}.topbar{position:static}.shell{max-width:none;padding:12px}.report-section[hidden]{display:block!important}tbody tr[hidden]{display:table-row!important}.case-item[hidden]{display:block!important}body{background:white;color:black}.panel,.metric,.table-panel,.hero{background:white;color:black;border:1px solid #bbb}th{background:#eee;color:black}}
""".strip()

_NAV = [('overview','▦','Overview'),('cases','⌕','Findings'),('timeline','▥','Timeline'),
        ('hosts','▣','Hosts'),('peers','⇄','Peer & Services'),('connections','≡','Connections'),
        ('dns','◎','DNS Activity'),('details','ⓘ','Capture Details')]


def _cell(text, *, value=None, numeric=False):
    raw = str(text if value is None else value)
    return '<td'+(' class="number"' if numeric else '')+' data-sort="'+_h(raw)+'">'+_h(text)+'</td>'


def _table(table_id, title, columns, rows, total, note, *, row_href=None):
    """columns = (label, name, sort-kind, presentation_fn)."""
    chunks = ['<div class="table-panel" data-table="'+_h(table_id)+'" data-total="'+str(total)+'">',
      '<div class="table-toolbar"><div><strong>'+_h(title)+'</strong><div class="muted">'+
      _n(len(rows))+' / '+_n(total)+' rows included in report</div></div>',
      '<div style="display:flex;gap:8px;align-items:center"><input type="search" data-table-search aria-label="'+_h(title)+' search" placeholder="Search this table..." autocomplete="off"><button class="small-button csv-button" data-table-csv type="button">CSV</button></div></div>',
      '<div class="table-wrap"><table><thead><tr>']
    for label, key, kind, fmt in columns:
        chunks.append('<th data-type="'+kind+'" aria-sort="none"><button type="button" class="sort-trigger" aria-label="'+_h(label)+' sort">'+_h(label)+'</button></th>')
    chunks.append('</tr></thead><tbody>')
    for row in rows:
        search = ' '.join(str(row.get(key,'')) for _,key,_,_ in columns)
        chunks.append('<tr data-search="'+_h(search)+'">')
        for label,key,kind,fmt in columns:
            v = row.get(key)
            rendered = fmt(v)
            sort = (_ip_sort(v) if kind=='ip' else (str(v or 0) if kind in ('number','time') else str(v or '')))
            if row_href == key and v is not None:
                chunks.append('<td data-sort="'+_h(sort)+'"><a href="#case-'+_h(v)+'">'+_h(rendered)+'</a></td>')
            else:
                chunks.append(_cell(rendered, value=sort, numeric=kind=='number'))
        chunks.append('</tr>')
    chunks.append('</tbody></table></div><div class="table-footer"><span data-table-count>'+_n(len(rows))+' HTML rows</span>')
    chunks.append('<div class="pager"><label>Page size <select data-page-size><option>25</option><option>50</option><option>100</option></select></label>')
    chunks.append('<button class="small-button" data-page-prev type="button" aria-label="Previous page">‹</button>')
    chunks.append('<span data-page-current>1 / 1</span><button class="small-button" data-page-next type="button" aria-label="Next page">›</button></div></div>')
    chunks.append('<p class="table-note">'+_h(note)+'</p></div>')
    return '\n'.join(chunks)




def _seconds(ns):
    if ns is None:
        return '—'
    sec = float(ns) / 1_000_000_000
    return f'{sec:,.1f}s' if sec >= 10 else f'{sec:,.2f}s'


def _endpoints(subject: dict, typ: str) -> tuple[str, str]:
    """Use only explicit packet/flow subject identities; do not infer a role."""
    source = subject.get('origin_ip') or subject.get('client_ip') or subject.get('local_ip') or '—'
    dest = (subject.get('responder_ip') or subject.get('resolver_ip') or
            subject.get('nonconfigured_destination_ip') or '—')
    port = subject.get('responder_port')
    if isinstance(port, int) and not isinstance(port, bool):
        dest = f'{dest}:{port}' if dest != '—' else f'Port {port} across multiple hosts'
    if typ == 'horizontal_port_scan_pattern':
        dest = f'Multiple hosts · TCP/{port}' if isinstance(port, int) else 'Multiple hosts'
    return str(source), str(dest)


def _evidence_summary(typ: str, finding: dict, evidence: list[dict]) -> str:
    """Data-driven one-line explanation, from stored detector evidence only."""
    by_type = {}
    for ev in evidence:
        by_type.setdefault(ev.get('type'), []).append(ev.get('metrics') or {})
    if typ in ('vertical_port_scan_pattern', 'horizontal_port_scan_pattern', 'mixed_port_scan_pattern'):
        geom = by_type.get('observed_scan_axis') or []
        if not geom:
            return 'Scan geometry evidence unavailable'
        dimensions = ('ports' if typ == 'vertical_port_scan_pattern' else 'hosts')
        # In multi-axis findings the primary evidence may be either axis.
        if typ == 'mixed_port_scan_pattern':
            dimensions = 'distinct targets'
        m = geom[0]
        return (f"{_n(m.get('unique_dimensions'))} {dimensions} · "
                f"{_n(m.get('attempt_flow_count'))} SYN-attempt flows · "
                f"{_n(m.get('explicit_rst_refusal_count'))} RST-refused")
    if typ == 'periodic_communication':
        timing = (by_type.get('interarrival_regularity') or [{}])[0]
        flowcount = finding.get('flow_count')
        if timing.get('median_interval_ns') is None:
            return 'Interarrival evidence unavailable'
        runs = int(timing.get('coherent_run_count') or 1)
        run_note = f" · {runs} separate observed runs" if runs > 1 else ''
        return (f"{_n(flowcount)} connections · "
                f"median gap {_seconds(timing.get('median_interval_ns'))} · "
                f"{100*float(timing.get('intervals_in_band_fraction') or 0):.0f}% intervals consistent"
                f"{run_note}")
    if typ == 'long_lived_tcp_flow_observed':
        m = (by_type.get('observed_single_tcp_flow_duration') or [{}])[0]
        if 'observed_duration_ns' not in m:
            return 'Duration evidence unavailable'
        return (f"Observed {_seconds(m['observed_duration_ns'])} · "
                f"{_size(m.get('captured_l4_payload_bytes'))} TCP payload")
    if typ == 'large_outbound_payload_observed':
        m = (by_type.get('observed_egress_payload') or [{}])[0]
        return f"{_size(m.get('captured_l4_payload_bytes'))} observed outbound payload" if m else 'Outbound volume evidence recorded'
    if typ == 'concentrated_nxdomain_diversity':
        m = next((m for group in by_type.values() for m in group if m.get('distinct_nxdomain_qnames') is not None), None)
        return (f"{_n(m['distinct_nxdomain_qnames'])} distinct NXDOMAIN names" if m else
                'Multiple matched NXDOMAIN responses')
    return 'Detector evidence available in details'


def _finding_rows(db: sqlite3.Connection, ncases: int):
    """Single index of *every* rendered case; no context rollups or extra DB stage."""
    cases = [json.loads(x[0]) for x in db.execute(
        'SELECT data_json FROM correlation_cases ORDER BY case_id LIMIT ?', (ncases,))]
    fid_set = {c.get('primary_finding_id') for c in cases if c.get('primary_finding_id')}
    findings = {}
    if fid_set:
        for fid, raw in db.execute('SELECT finding_id,finding_json FROM detector_findings'):
            if fid in fid_set:
                findings[fid] = json.loads(raw)
    evs = {}
    has_evidence = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='detector_evidence'").fetchone()
    for (raw,) in (db.execute('SELECT data_json FROM detector_evidence') if has_evidence else ()):
        ev = json.loads(raw)
        if ev.get('finding_id') in fid_set:
            evs.setdefault(ev['finding_id'], []).append(ev)
    rows = []
    for c in cases:
        fid = c.get('primary_finding_id')
        f = findings.get(fid, {})
        typ = c.get('primary_type') or f.get('type') or 'unknown'
        subject = c.get('primary_subject') or f.get('subject') or {}
        src, dst = _endpoints(subject, typ)
        row = dict(id=c['case_id'], behavior=_type_label(typ), source=src,
                   dest=dst, why=_evidence_summary(typ, f, evs.get(fid, [])),
                   first=c.get('observed_first_ns'), last=c.get('observed_last_ns'))
        rows.append((row,c,f,evs.get(fid, [])))
    return rows


def write_html_report(report: dict, index_path: str | Path, output_path: str | Path, *,
                      max_cases: int | None = None, overwrite: bool = False,
                      table_limit: int = TABLE_LIMIT) -> dict:
    """Render a single English-language offline report from the transient index."""
    if max_cases is not None and (type(max_cases) is not int or max_cases < 0):
        raise ValueError('max_cases must be nonnegative or None')
    if type(table_limit) is not int or not 1 <= table_limit <= TABLE_LIMIT:
        raise ValueError('table_limit must be an integer from 1 to 1000')
    output_path, index_path = Path(output_path), Path(index_path)
    if output_path.resolve() == index_path.resolve():
        raise ValueError('HTML and index paths must be different')
    if output_path.exists() and not overwrite:
        raise FileExistsError('HTML report exists; pass --overwrite')
    output_path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(index_path.resolve().as_uri()+'?mode=ro',uri=True)
    db.row_factory=sqlite3.Row
    try:
        total=db.execute('SELECT COUNT(*) FROM correlation_cases').fetchone()[0]
        ncases=total if max_cases is None else min(total,max_cases)
        findings=_finding_rows(db,ncases)
        dashboard=collect_dashboard(db,report['capture'],limit=table_limit)
        types=Counter(x[1].get('primary_type','unknown') for x in findings)
        csp_hash=base64.b64encode(sha256(_UI_JS.encode()).digest()).decode()
        csp=("default-src 'none'; script-src 'sha256-"+csp_hash+
             "'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'")
        capture,summary=report['capture'],report['summary']
        with output_path.open('w',encoding='utf-8') as out:
            def w(value):out.write(value+'\n')
            w('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
            w('<meta http-equiv="Content-Security-Policy" content="'+_h(csp)+'">')
            w('<title>PCAP Behavior Core · Offline forensic report</title><style>'+_UI_CSS+'</style></head><body>')
            w('<div id="app" class="app"><aside id="sidebar" class="sidebar" aria-label="Main navigation">')
            w('<div class="brand"><span class="brand-logo" aria-hidden="true">◇</span><span class="brand-text">PCAP Behavior Core</span></div>')
            for i,(sid,icon,title) in enumerate(_NAV):
                if i in (2,6,7):
                    w('<div class="nav-caption">'+{2:'TRAFFIC',6:'PROTOCOLS',7:'REPORT'}[i]+'</div>')
                w('<a class="side-link" href="#'+sid+'" data-title="'+_h(title)+'" title="'+_h(title)+'"><span class="side-icon" aria-hidden="true">'+_h(icon)+'</span><span class="side-text">'+_h(title)+'</span></a>')
            w('</aside><div class="app-main"><header class="topbar"><div><div class="eyebrow">Local, offline report</div><div id="current-section" class="topbar-title">Overview</div></div>')
            w('<div class="top-actions"><span class="topbar-meta">'+_h(Path(capture.get('source_path','capture.pcap')).name)+'</span>')
            w('<button id="mobile-menu" class="small-button mobile-only" type="button" aria-label="Open menu">☰</button>')
            w('<button id="sidebar-toggle" class="small-button" type="button" aria-label="Toggle sidebar">☷</button></div></header>')
            w('<main class="shell">')
            # 1. Overview: facts, without repetitive disclaimers.
            w('<section id="overview" class="report-section"><div class="section-head"><div><div class="eyebrow">Capture summary</div><h1>Network behavior overview</h1>')
            w('<p>Capture statistics and observed traffic patterns.</p></div></div>')
            w('<div class="hero"><div class="eyebrow">Capture Time (UTC)</div><div class="capture-clock"><div class="clock-range">'+
              _capture_time_html(capture.get('first_ts_ns'))+' <span aria-hidden="true">→</span> '+_capture_time_html(capture.get('last_ts_ns'))+'</div>')
            w('<div class="clock-note">First and last recorded packet timestamps</div></div><div class="muted">'+_h(Path(capture.get('source_path','capture.pcap')).name)+'</div></div>')
            w('<div class="metric-grid">')
            for label,value in [('Packets',_n(capture.get('packet_count'))),('Flows',_n(summary.get('flow_count'))),
                                ('DNS transactions',_n(summary.get('dns_transaction_count'))),('Behavior findings',_n(total))]:
                w('<div class="metric"><div class="label">'+_h(label)+'</div><div class="value">'+_h(value)+'</div></div>')
            w('</div><div class="panel"><h3>Behavior breakdown</h3><div class="bars">')
            if not types:
                w('<p class="muted">No detector findings in this capture.</p>')
            for typ,n in sorted(types.items(),key=lambda x:(-x[1],x[0])):
                pct=round(100*n/max(1,ncases),2)
                w('<div class="bar-row"><span>'+_h(_type_label(typ))+'</span><div class="track"><div class="fill" style="width:'+str(pct)+'%"></div></div><span class="count">'+_n(n)+'</span></div>')
            w('</div></div></section>')
            # 2. Findings: first sight is the main sortable, searchable evidence index.
            w('<section id="cases" class="report-section"><div class="section-head"><div><h1>Findings</h1>')
            w('<p>Behavior, endpoints, and observed evidence—without opening each record.</p></div><span class="tag">'+_n(ncases)+' / '+_n(total)+' findings</span></div>')
            if ncases<total:
                w('<div class="notice">Explicit HTML limit: '+_n(ncases)+' of '+_n(total)+' findings included. Filters cover included rows only.</div>')
            rows=[x[0] for x in findings]
            w(_table('findings-index','All findings',[
                ('Behavior','behavior','text',str),('Source','source','ip',str),('Destination / service','dest','text',str),
                ('Observed evidence','why','text',str),('First seen (UTC)','first','time',_utc),
                ('Last seen (UTC)','last','time',_utc),('Details','id','text',lambda v:'View evidence')],
                rows,total,'One row per retained case. Scan counts represent probe patterns, not individual SYN packets.',row_href='id'))
            w('<details id="finding-details" class="panel nested"><summary>Supporting evidence and packet references ('+_n(ncases)+')</summary>')
            for row,case,finding,evidence in findings:
                cid=row['id'];fid=case.get('primary_finding_id')
                search=' '.join(str(row.get(k,'')) for k in ('behavior','source','dest','why','id'))
                w('<details class="case-item" id="case-'+_h(cid)+'" data-type="'+_h(case.get('primary_type','unknown'))+'" data-search="'+_h(search)+'">')
                w('<summary><div><span class="case-title">'+_h(row['behavior'])+'</span>')
                w('<div class="case-sub"><span>'+_h(row['source'])+' → '+_h(row['dest'])+'</span><span class="tag">'+_h(row['why'])+'</span></div></div></summary>')
                w('<div class="case-body"><div class="case-meta">')
                for label,val in [('Case ID',cid),('Finding ID',fid or '—'),('First seen',_utc(row['first'])),
                                  ('Last seen',_utc(row['last'])),('Linked flows',finding.get('flow_count','—'))]:
                    w('<div><div class="k">'+_h(label)+'</div><div class="v">'+_h(val)+'</div></div>')
                w('</div><h3>Detector measurements</h3>')
                if evidence:
                    for ev in evidence:
                        w('<details class="nested"><summary>'+_h(str(ev.get('type','Evidence')).replace('_',' '))+'</summary><pre class="evidence-json">'+
                          _h(json.dumps(ev.get('metrics',{}),ensure_ascii=False,indent=2,sort_keys=True))+'</pre></details>')
                else:
                    w('<p class="muted">No structured evidence metrics available in the index.</p>')
                if case.get('supporting_findings'):
                    w('<h3>Linked detector findings</h3><ul class="detail-list">')
                    for sup in case['supporting_findings']:
                        w('<li>'+_h(_type_label(sup.get('type')))+' · '+_h(sup.get('finding_id',''))+'</li>')
                    w('</ul>')
                frames=finding.get('packet_frame_samples') or []
                if not frames and fid:
                    frames=[r[0] for r in db.execute('SELECT DISTINCT frame_no FROM detector_finding_packets WHERE finding_id=? ORDER BY frame_no LIMIT 16',(fid,))]
                w('<h3>Sample PCAP frame numbers</h3><code>'+_h(', '.join(map(str,frames)) if frames else 'Not available')+'</code>')
                w('<p class="extra">Full packet contents remain in the original PCAP.</p></div></details>')
            w('</details>')
            if not total:
                w('<div class="panel">No findings were produced by the currently implemented detector types.</div>')
            w('</section>')
            # Remaining read-only traffic views. No invented interpretations.
            times=dashboard['timeline'];peak=max((x['packets'] for x in times),default=0)
            w('<section id="timeline" class="report-section"><div class="section-head"><div><h1>Timeline</h1><p>All recorded packets are included in the activity distribution.</p></div></div>')
            w('<div class="panel"><h3>Packet activity across capture</h3><div class="timeline" role="img" aria-label="Packet activity over time">')
            for x in times:
                height=max(2,round(100*x['packets']/peak,2)) if peak else 2
                tip=f"{_utc(x['start'])} — {_utc(x['end'])}: {_n(x['packets'])} packets"
                w('<span class="bin" style="height:'+str(height)+'%" title="'+_h(tip)+'" aria-label="'+_h(tip)+'"></span>')
            w('</div><div class="timeline-labels"><span>'+_h(_utc(capture.get('first_ts_ns')))+'</span><span>'+_h(_utc(capture.get('last_ts_ns')))+'</span></div></div></section>')
            w('<section id="hosts" class="report-section"><div class="section-head"><div><h1>Host Activity</h1><p>Observed IP addresses, payload and peer counts.</p></div></div>')
            w(_table('hosts','Host activity',[
                ('IP Address','ip','ip',str),('Sent payload','sent','number',_size),('Received payload','received','number',_size),
                ('Involved packets','packets','number',_n),('Flows','flows','number',_n),('Distinct peers','peer_count','number',_n)],
                dashboard['hosts'],dashboard['host_total'],'Payload counts reflect captured L4 bytes, including possible retransmissions.'))
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='context_hosts'").fetchone():
                contexts=[json.loads(x[0]) for x in db.execute('SELECT data_json FROM context_hosts ORDER BY host_ip LIMIT 50')]
                if contexts:
                    w('<details class="panel nested"><summary>Host context ('+_n(len(contexts))+' entries shown)</summary>')
                    for ctx in contexts:
                        w('<div class="context-item"><strong>'+_h(ctx.get('host_ip',''))+'</strong> · '+_n(ctx.get('finding_count'))+
                          ' related findings · '+_n(ctx.get('distinct_explicit_peer_ip_count'))+' distinct peer IPs</div>')
                    w('</details>')
            w('</section>')
            w('<section id="peers" class="report-section"><div class="section-head"><div><h1>Peer &amp; Services</h1><p>Observed origin–responder pairs and destination services.</p></div></div>')
            w(_table('peers','Peer and service activity',[
                ('Origin IP','origin','ip',str),('Responder IP','responder','ip',str),('Protocol','protocol','text',str),
                ('Responder port','port','number',str),('Flows','flows','number',_n),('Packets','packets','number',_n),
                ('Sent payload','sent','number',_size),('Received payload','received','number',_size)],
                dashboard['peers'],dashboard['peer_total'],'Flow direction follows the observed origin/responder fields.'))
            w('</section>')
            w('<section id="connections" class="report-section"><div class="section-head"><div><h1>Connections</h1><p>Representative flows selected across packet, byte and duration dimensions.</p></div></div>')
            w(_table('connections','Selected flow observations',[
                ('Origin IP','origin','ip',str),('Origin port','origin_port','number',str),('Responder IP','responder','ip',str),
                ('Dest port','port','number',str),('Protocol','protocol','text',str),('Packets','packets','number',_n),
                ('Observed IP bytes','bytes','number',_size),('First seen','first','time',_utc),('TCP state','state','text',str)],
                dashboard['connections'],dashboard['connection_total'],'A reconstructed flow does not necessarily mean a completed TCP connection.'))
            ftp = report.get('protocol_observations', {}).get('ftp_control', {})
            if ftp.get('sessions_observed'):
                w('<div class="panel"><h3>Observed FTP control traffic</h3>')
                w('<p class="muted">Visible plaintext FTP command names and response codes only. '
                  'Command arguments, credentials and paths are not retained. '
                  'A transfer command does not establish a completed transfer or security incident.</p>')
                ftp_rows = []
                for sess in ftp.get('sessions', []):
                    cmds = ', '.join(f'{k} × {v}' for k,v in sess['observed_commands'].items()) or '—'
                    replies = ', '.join(f'{k} × {v}' for k,v in sess['observed_reply_codes'].items()) or '—'
                    ftp_rows.append(dict(client=sess['client_ip'],server=sess['server_ip'],
                                         port=21,commands=cmds,replies=replies,
                                         frames=', '.join(map(str,sess['packet_refs'])),
                                         limited='Yes' if sess['observation_limited'] else 'No'))
                w(_table('ftp-control','FTP control observations',[
                    ('Client IP','client','ip',str),('Server IP','server','ip',str),
                    ('Port','port','number',str),('Commands','commands','text',str),
                    ('Response codes','replies','text',str),('Frame references','frames','text',str),
                    ('Partial','limited','text',str)], ftp_rows,ftp['sessions_observed'],
                    'Only indexed, contiguous TCP control lines are interpreted.'))
                w('</div>')
            w('</section>')
            w('<section id="dns" class="report-section"><div class="section-head"><div><h1>DNS Activity</h1><p>Observed query and matched response data.</p></div></div>')
            w('<div class="metric-grid">')
            for label,val in [('Observed DNS queries',dashboard['dns_query_total']),('Distinct QNAMEs',dashboard['dns_total']),
                              ('Matched NXDOMAIN',summary.get('observed_matched_nxdomain_count')),('DNS transactions',summary.get('dns_transaction_count'))]:
                w('<div class="metric"><div class="label">'+_h(label)+'</div><div class="value">'+_n(val)+'</div></div>')
            w('</div>')
            w(_table('dns','DNS query observations',[
                ('Domain / QNAME','name','text',str),('Queries','queries','number',_n),
                ('Matched NXDOMAIN','nxdomain','number',_n),('Unanswered','unanswered','number',_n),
                ('Distinct clients','clients','number',_n),('First query','first','time',_utc)],
                dashboard['dns'],dashboard['dns_total'],'Only matched NXDOMAIN responses contribute to the NXDOMAIN column.'))
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='context_dns_findings'").fetchone():
                contexts=[json.loads(x[0]) for x in db.execute('SELECT data_json FROM context_dns_findings ORDER BY finding_id LIMIT 50')]
                if contexts:
                    w('<details class="panel nested"><summary>DNS finding context ('+_n(len(contexts))+' entries shown)</summary>')
                    for ctx in contexts:
                        state=ctx.get('client_resolver_capture_context') or {}
                        w('<div class="context-item">'+_h(ctx.get('client_ip',''))+' → '+_h(ctx.get('resolver_ip',''))+
                          ' · Matched NXDOMAIN: '+_n(ctx.get('exact_matched_nxdomain_transaction_count'))+
                          ' · Unanswered: '+_n(state.get('unanswered_queries'))+'</div>')
                    w('</details>')
            w('</section>')
            w('<section id="details" class="report-section"><div class="section-head"><div><h1>Capture Details</h1><p>File identity, engine settings and analysis limitations.</p></div></div>')
            w('<div class="panel"><div class="case-meta">')
            for label,val in [('File',Path(capture.get('source_path','')).name),('Capture ID',capture.get('capture_id','—')),
                              ('SHA-256',capture.get('sha256','—')),('File size',_size(capture.get('file_size_bytes'))),
                              ('Observed packets',_n(capture.get('packet_count'))),
                              ('Capture start (UTC)',_utc(capture.get('first_ts_ns'))),('Capture end (UTC)',_utc(capture.get('last_ts_ns'))),
                              ('Linktype',capture.get('linktype','—'))]:
                w('<div><div class="k">'+_h(label)+'</div><div class="v">'+_h(val)+'</div></div>')
            w('</div></div><div class="panel"><h3>Detector execution</h3>')
            for d in report.get('detector_evaluations',[]):
                w('<div class="context-item">'+_h(d.get('detector_id','?'))+' — '+_h(d.get('status','?'))+'</div>')
            w('<h3>Capture warnings</h3>')
            warnings=report.get('warnings',[])
            if not warnings: w('<p class="muted">None recorded.</p>')
            for item in warnings[:50]: w('<p><code>'+_h(json.dumps(item,ensure_ascii=False,sort_keys=True))+'</code></p>')
            w('<h3>Analysis limitations</h3><p class="muted">The engine reports observed behaviors, not malware attribution. '
              'Incomplete captures, unseen TCP handshakes, and unanswered DNS queries can limit interpretation. '
              'Detailed packet contents remain in the original PCAP; the HTML is independent of SQLite.</p></div></section>')
            w('<footer class="footer">Offline report · No external services · No risk scores · Original PCAP preserved</footer>')
            w('</main></div></div><script>'+_UI_JS+'</script></body></html>')
        return dict(path=str(output_path),rendered_cases=ncases,total_cases=total,
                    preview_truncated=ncases<total,external_dependencies=False,
                    traffic_tables={k:dict(shown=len(dashboard[k]),total=dashboard[{'hosts':'host_total','peers':'peer_total',
                    'connections':'connection_total','dns':'dns_total'}[k]]) for k in ('hosts','peers','connections','dns')},
                    timeline_packet_count=dashboard['timeline_packets'])
    finally:
        db.close()
