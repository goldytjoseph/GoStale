package main

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Subdomain Footprint Report — %s</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f7f9fc;
    color: #1f2937;
    margin: 0;
    padding: 0;
  }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
  header {
    background: linear-gradient(135deg, #4f46e5 0%%, #7c3aed 100%%);
    color: white;
    padding: 32px 24px;
    border-radius: 0 0 12px 12px;
  }
  header h1 { margin: 0 0 8px 0; font-size: 28px; }
  header .meta { opacity: 0.9; font-size: 14px; }
  .stats {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    margin: 24px 0;
  }
  .stat-card {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    border-left: 4px solid #4f46e5;
  }
  .stat-card.critical { border-left-color: #dc2626; }
  .stat-card.high { border-left-color: #ea580c; }
  .stat-card.medium { border-left-color: #ca8a04; }
  .stat-card.low { border-left-color: #16a34a; }
  .stat-card .number { font-size: 32px; font-weight: 700; margin: 0; }
  .stat-card .label { font-size: 12px; text-transform: uppercase; color: #6b7280; letter-spacing: 0.5px; }
  .controls {
    background: white;
    padding: 16px;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    margin-bottom: 16px;
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    align-items: center;
  }
  .controls input, .controls select {
    padding: 8px 12px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    font-size: 14px;
  }
  .controls input[type=text] { flex: 1; min-width: 200px; }
  .controls button {
    padding: 8px 16px;
    background: #4f46e5;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
  }
  .controls button:hover { background: #4338ca; }
  table {
    width: 100%%;
    background: white;
    border-collapse: collapse;
    border-radius: 10px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    font-size: 13px;
  }
  th {
    background: #f3f4f6;
    text-align: left;
    padding: 12px;
    font-weight: 600;
    color: #374151;
    border-bottom: 2px solid #e5e7eb;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }
  th:hover { background: #e5e7eb; }
  th .arrow { opacity: 0.4; font-size: 10px; margin-left: 4px; }
  td {
    padding: 12px;
    border-bottom: 1px solid #f3f4f6;
    vertical-align: top;
  }
  tr:hover td { background: #fafbfd; }
  .severity {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
  }
  .sev-Critical { background: #fee2e2; color: #991b1b; }
  .sev-High { background: #ffedd5; color: #9a3412; }
  .sev-Medium { background: #fef3c7; color: #854d0e; }
  .sev-Low { background: #dcfce7; color: #166534; }
  .tag {
    display: inline-block;
    padding: 2px 6px;
    margin: 2px;
    background: #eef2ff;
    color: #4338ca;
    border-radius: 4px;
    font-size: 11px;
  }
  .copy-btn {
    cursor: pointer;
    background: none;
    border: 1px solid #d1d5db;
    border-radius: 4px;
    padding: 2px 6px;
    font-size: 11px;
    color: #6b7280;
    margin-left: 4px;
  }
  .copy-btn:hover { background: #f3f4f6; color: #1f2937; }
  .copy-btn.copied { background: #16a34a; color: white; border-color: #16a34a; }
  .url-cell a { color: #4f46e5; text-decoration: none; word-break: break-all; }
  .url-cell a:hover { text-decoration: underline; }
  .ip-mono { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; }
  details summary { cursor: pointer; color: #4f46e5; font-size: 12px; }
  details > div { margin-top: 6px; padding: 8px; background: #f9fafb; border-radius: 4px; font-size: 12px; }
  .year-bad { color: #dc2626; font-weight: 600; }
  .smart-score {
    display: inline-block;
    padding: 2px 8px;
    background: #fef3c7;
    color: #854d0e;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
    margin-top: 4px;
  }
  .footer { text-align: center; color: #9ca3af; padding: 24px; font-size: 12px; }
  .export-btn {
    background: #16a34a !important;
  }
  .export-btn:hover { background: #15803d !important; }
  .empty { text-align: center; padding: 40px; color: #9ca3af; }
  .screenshot-link { color: #6b7280; font-size: 11px; }
  @media (max-width: 900px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    table { font-size: 11px; }
    th, td { padding: 8px; }
  }
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>🔍 Subdomain Footprint Report</h1>
    <div class="meta">
      <strong>Target:</strong> %s &nbsp;|&nbsp;
      <strong>Filter:</strong> %s &nbsp;|&nbsp;
      <strong>Generated:</strong> %s
    </div>
  </div>
</header>

<div class="container">
  <div class="stats">
    <div class="stat-card"><p class="label">Total Hosts</p><p class="number" id="stat-total">%d</p></div>
    <div class="stat-card critical"><p class="label">Critical</p><p class="number">%d</p></div>
    <div class="stat-card high"><p class="label">High</p><p class="number">%d</p></div>
    <div class="stat-card medium"><p class="label">Medium</p><p class="number">%d</p></div>
    <div class="stat-card low"><p class="label">Low</p><p class="number">%d</p></div>
  </div>

  <div class="controls">
    <input type="text" id="search" placeholder="🔎 Filter by hostname, IP, title, tech, tag..." oninput="renderTable()">
    <select id="sevFilter" onchange="renderTable()">
      <option value="">All Severities</option>
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <button onclick="copyAllIPs()">📋 Copy All IPs</button>
    <button onclick="copyAllHosts()">📋 Copy All Hostnames</button>
    <button class="export-btn" onclick="exportFiltered()">⬇ Export Filtered JSON</button>
  </div>

  <table id="report">
    <thead>
      <tr>
        <th onclick="sortBy('Severity')">Severity <span class="arrow">⇅</span></th>
        <th onclick="sortBy('Hostname')">Host / URL <span class="arrow">⇅</span></th>
        <th onclick="sortBy('IP')">IP : Port <span class="arrow">⇅</span></th>
        <th onclick="sortBy('StatusCode')">Status <span class="arrow">⇅</span></th>
        <th>Title</th>
        <th onclick="sortBy('OldestYear')">Year Found <span class="arrow">⇅</span></th>
        <th>Tech / Server</th>
        <th>CDN / WAF / TLS</th>
        <th>Tags</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <div id="empty-msg" class="empty" style="display:none;">No results match your filter.</div>
</div>

<div class="footer">Report generated by Subdomain Footprint Scanner v2.0</div>

<script>
const DATA = %s;
let currentSort = { key: 'Severity', dir: 'desc' };
const sevOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };

function copyText(txt, btn) {
  navigator.clipboard.writeText(txt).then(() => {
    if (btn) {
      const o = btn.textContent;
      btn.textContent = '✓';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = o; btn.classList.remove('copied'); }, 1200);
    }
  });
}

function copyAllIPs() {
  const filtered = getFiltered();
  const ips = [...new Set(filtered.map(r => r.ip).filter(Boolean))].join('\n');
  copyText(ips);
  alert('Copied ' + ips.split('\n').length + ' IPs to clipboard');
}

function copyAllHosts() {
  const filtered = getFiltered();
  const hosts = [...new Set(filtered.map(r => r.hostname))].join('\n');
  copyText(hosts);
  alert('Copied ' + hosts.split('\n').length + ' hostnames to clipboard');
}

function exportFiltered() {
  const filtered = getFiltered();
  const blob = new Blob([JSON.stringify(filtered, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'filtered-results.json';
  a.click();
  URL.revokeObjectURL(url);
}

function getFiltered() {
  const q = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  return DATA.filter(r => {
    if (sev && r.severity !== sev) return false;
    if (!q) return true;
    const hay = [
      r.hostname, r.ip, r.title, r.server, r.cdn, r.waf,
      (r.tech_stack||[]).join(' '),
      (r.tags||[]).join(' '),
      (r.discovery_source||[]).join(' ')
    ].join(' ').toLowerCase();
    return hay.includes(q);
  });
}

function sortBy(key) {
  const map = { 'Severity': 'severity', 'Hostname': 'hostname', 'IP': 'ip',
                'StatusCode': 'status_code', 'OldestYear': 'oldest_year' };
  const k = map[key];
  if (currentSort.key === key) {
    currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    currentSort.key = key;
    currentSort.dir = key === 'OldestYear' ? 'asc' : 'desc';
  }
  renderTable();
}

function renderTable() {
  let rows = getFiltered();
  const k = { 'Severity': 'severity', 'Hostname': 'hostname', 'IP': 'ip',
              'StatusCode': 'status_code', 'OldestYear': 'oldest_year' }[currentSort.key];
  rows.sort((a, b) => {
    let va = a[k], vb = b[k];
    if (k === 'severity') { va = sevOrder[va]||0; vb = sevOrder[vb]||0; }
    if (typeof va === 'string') return currentSort.dir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    return currentSort.dir === 'asc' ? va - vb : vb - va;
  });

  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  document.getElementById('empty-msg').style.display = rows.length === 0 ? 'block' : 'none';

  rows.forEach(r => {
    const tr = document.createElement('tr');
    const ipPort = (r.ip || r.hostname) + ':' + r.port;
    tr.innerHTML =
      '<td><span class="severity sev-' + r.severity + '">' + r.severity + '</span></td>' +
      '<td class="url-cell"><a href="' + escapeHtml(r.url) + '" target="_blank">' + escapeHtml(r.hostname) + '</a>' +
        ' <button class="copy-btn" data-copy="' + escapeHtml(r.url) + '">copy</button></td>' +
      '<td><span class="ip-mono">' + escapeHtml(ipPort) + '</span>' +
        ' <button class="copy-btn" data-copy="' + escapeHtml(ipPort) + '">copy</button></td>' +
      '<td>' + r.status_code + '</td>' +
      '<td>' + escapeHtml(r.title || '—') + '</td>' +
      '<td><span class="year-bad">' + r.oldest_year + '</span>' +
        (r.latest_year !== r.oldest_year ? ' — ' + r.latest_year : '') +
        (r.smart_score ? '<br><span class="smart-score" title="Smart-mode score">★ ' + r.smart_score + '</span>' : '') +
        '</td>' +
      '<td>' + escapeHtml((r.tech_stack||[]).join(', ') || '—') +
        '<br><small style="color:#9ca3af">' + escapeHtml(r.server || '') + '</small></td>' +
      '<td>' + (r.cdn ? '<small>CDN: ' + escapeHtml(r.cdn) + '</small><br>' : '') +
        (r.waf ? '<small>WAF: ' + escapeHtml(r.waf) + '</small><br>' : '') +
        '<small style="color:' + (r.tls_valid ? '#16a34a' : '#dc2626') + '">' +
        (r.tls_valid ? '✓ TLS OK' : '✗ TLS Invalid') +
        (r.tls_expiry ? ' (' + escapeHtml(r.tls_expiry) + ')' : '') + '</small></td>' +
      '<td>' + (r.tags||[]).map(t => '<span class="tag">' + escapeHtml(t) + '</span>').join('') + '</td>' +
      '<td><details><summary>view</summary><div>' +
        '<b>DNS A:</b> ' + escapeHtml(((r.dns && r.dns.a) || []).join(', ')) + '<br>' +
        '<b>CNAME:</b> ' + escapeHtml((r.dns && r.dns.cname) || '—') + '<br>' +
        '<b>MX:</b> ' + escapeHtml((((r.dns && r.dns.mx) || []).join(', ')) || '—') + '<br>' +
        '<b>Favicon Hash:</b> <code style="font-size:10px">' + escapeHtml(r.favicon_hash || '—') + '</code><br>' +
        '<b>Sources:</b> ' + escapeHtml((r.discovery_source||[]).join(', ')) + '<br>' +
        '<b>Years Found:</b> ' + escapeHtml((r.copyright_years||[]).join(', ')) + '<br>' +
        '<b>Size:</b> ' + r.content_length + ' bytes<br>' +
        (r.smart_reasons && r.smart_reasons.length ?
          '<b>🧠 Smart-mode reasons:</b><ul style="margin:4px 0 4px 18px;padding:0">' +
          r.smart_reasons.map(x => '<li>' + escapeHtml(x) + '</li>').join('') +
          '</ul>' : '') +
        '<a class="screenshot-link" href="' + escapeHtml(r.screenshot_url) + '" target="_blank">📸 View screenshot →</a>' +
      '</div></details></td>';
    tbody.appendChild(tr);
  });
}

// Event delegation for copy buttons inside the table
document.addEventListener('click', e => {
  const btn = e.target.closest('.copy-btn[data-copy]');
  if (btn) copyText(btn.getAttribute('data-copy'), btn);
});

function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

renderTable();
</script>
</body>
</html>
`
