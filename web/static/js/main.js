// OPTISEC Recon Pro — Main JS

const API = {
  async post(url, data) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return r.json();
  },
  async get(url) {
    const r = await fetch(url);
    return r.json();
  },
  async delete(url) {
    const r = await fetch(url, { method: 'DELETE' });
    return r.json();
  },
  async patch(url, data) {
    const r = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return r.json();
  }
};

// Tabs
function initTabs() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const group = tab.closest('.tabs').dataset.group || tab.dataset.group;
      const target = tab.dataset.tab;
      document.querySelectorAll(`.tab[data-group="${group}"], .tab[data-tab]`).forEach(t => {
        if (t.closest('.tabs') === tab.closest('.tabs')) t.classList.remove('active');
      });
      tab.classList.add('active');
      document.querySelectorAll('.tab-content').forEach(c => {
        if (c.dataset.tab === target) c.classList.add('active');
        else if (tab.closest('.tabs').parentElement.contains(c)) c.classList.remove('active');
      });
    });
  });
}

// Severity badge helper
function severityBadge(sev) {
  const cls = { Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Info: 'info' };
  return `<span class="badge badge-${(cls[sev] || 'info')}">${sev}</span>`;
}

// Toast notifications
function toast(msg, type = 'success') {
  const el = document.createElement('div');
  el.className = `alert alert-${type}`;
  el.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;min-width:280px;animation:fadeIn 0.2s';
  el.innerHTML = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// Scan page
window.startScan = async function() {
  const target = document.getElementById('scan-target')?.value?.trim();
  if (!target) { toast('Please enter a target', 'error'); return; }

  const scanTypes = [...document.querySelectorAll('.scan-type:checked')].map(cb => cb.value);
  const btn = document.getElementById('scan-btn');
  const status = document.getElementById('scan-status');
  const results = document.getElementById('scan-results');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scanning...';
  if (status) status.innerHTML = '<div class="alert alert-info">Scan started. This may take a few minutes...</div>';
  if (results) results.innerHTML = '';

  const progressFill = document.getElementById('progress-fill');
  let prog = 0;
  const progInterval = setInterval(() => {
    prog = Math.min(prog + Math.random() * 3, 90);
    if (progressFill) progressFill.style.width = prog + '%';
  }, 800);

  try {
    const { scan_id } = await API.post('/api/scan', { target, scan_types: scanTypes });
    window._currentScanId = scan_id;

    const poll = setInterval(async () => {
      const data = await API.get(`/api/scan/${scan_id}`);
      if (data.status === 'completed' || data.status === 'error') {
        clearInterval(poll);
        clearInterval(progInterval);
        if (progressFill) progressFill.style.width = '100%';
        btn.disabled = false;
        btn.innerHTML = '▶ Start Scan';

        if (data.status === 'error') {
          if (status) status.innerHTML = `<div class="alert alert-error">Error: ${data.error}</div>`;
          return;
        }
        if (status) status.innerHTML = '<div class="alert alert-success">Scan completed!</div>';
        renderScanResults(data.results, target);
      }
    }, 2000);
  } catch (e) {
    clearInterval(progInterval);
    btn.disabled = false;
    btn.innerHTML = '▶ Start Scan';
    if (status) status.innerHTML = `<div class="alert alert-error">${e.message}</div>`;
  }
};

function renderScanResults(results, target) {
  const el = document.getElementById('scan-results');
  if (!el) return;

  const vulns = results.vulnerabilities || [];
  const subs = results.subdomains || [];
  const nmapPorts = (results.nmap || {}).ports || [];
  const dns = results.dns || {};
  const osint = results.osint || {};
  const ssl = results.ssl || null;
  const headers = results.headers || null;
  const portScan = results.ports || null;

  const sevCount = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  vulns.forEach(v => { if (sevCount[v.severity] !== undefined) sevCount[v.severity]++; });

  const openPortsCount = portScan ? (portScan.open_count || 0) : nmapPorts.length;

  let html = `
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-value">${vulns.length}</div><div class="stat-label">Vulnerabilities</div></div>
    <div class="stat-card critical"><div class="stat-value">${sevCount.Critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card high"><div class="stat-value">${sevCount.High}</div><div class="stat-label">High</div></div>
    <div class="stat-card info"><div class="stat-value">${subs.length}</div><div class="stat-label">Subdomains</div></div>
  </div>

  <div class="tabs" data-group="results">
    <div class="tab active" data-tab="vulns" data-group="results">Vulnerabilities (${vulns.length})</div>
    <div class="tab" data-tab="subs" data-group="results">Subdomains (${subs.length})</div>
    <div class="tab" data-tab="ports-tab" data-group="results">Ports (${openPortsCount})</div>
    <div class="tab" data-tab="ssl-tab" data-group="results">SSL/TLS</div>
    <div class="tab" data-tab="headers-tab" data-group="results">HTTP Headers${headers ? ' ('+headers.grade+')' : ''}</div>
    <div class="tab" data-tab="dns-tab" data-group="results">DNS</div>
    <div class="tab" data-tab="osint-tab" data-group="results">OSINT</div>
  </div>`;

  // Vulns
  html += `<div class="tab-content active" data-tab="vulns">`;
  if (vulns.length === 0) {
    html += `<div class="alert alert-success">No vulnerabilities found.</div>`;
  } else {
    html += `<div class="table-wrap"><table><thead><tr><th>Type</th><th>Severity</th><th>Parameter</th><th>URL</th><th>Evidence</th></tr></thead><tbody>`;
    vulns.forEach(v => {
      html += `<tr>
        <td><strong>${esc(v.type)}</strong></td>
        <td>${severityBadge(v.severity)}</td>
        <td class="mono">${esc(v.parameter || '')}</td>
        <td class="mono dim">${esc((v.url || '').substring(0, 60))}…</td>
        <td class="dim">${esc(v.evidence || '')}</td>
      </tr>`;
    });
    html += `</tbody></table></div>`;
  }
  html += `</div>`;

  // Subdomains
  html += `<div class="tab-content" data-tab="subs"><div class="table-wrap"><table><thead><tr><th>Subdomain</th><th>IP</th></tr></thead><tbody>`;
  subs.forEach(s => { html += `<tr><td class="mono">${esc(typeof s==='object'?s.subdomain:s)}</td><td class="mono dim">${esc(typeof s==='object'?s.ip:'')}</td></tr>`; });
  html += `</tbody></table></div></div>`;

  // Ports
  html += `<div class="tab-content" data-tab="ports-tab">`;
  if (portScan) {
    const openPorts = portScan.open_ports || [];
    html += `<div style="margin-bottom:12px;display:flex;gap:12px;align-items:center">
      <span>Scanned: <strong>${portScan.ports_scanned}</strong></span>
      <span>Open: <strong style="color:var(--accent)">${portScan.open_count}</strong></span>
      <span>High-Risk: <strong style="color:var(--danger)">${portScan.high_risk_count}</strong></span>
      <span class="badge badge-${portScan.risk_label==='HIGH'?'critical':portScan.risk_label==='MEDIUM'?'high':'low'}">${portScan.risk_label}</span>
    </div>`;
    if (portScan.notes && portScan.notes.length) {
      portScan.notes.forEach(n => { html += `<div class="alert alert-info" style="font-size:12px;margin-bottom:4px">• ${esc(n)}</div>`; });
    }
    html += `<div class="table-wrap"><table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Banner</th></tr></thead><tbody>`;
    openPorts.forEach(p => {
      html += `<tr>
        <td class="mono accent">${esc(String(p.port))}</td>
        <td>${esc(p.service)}</td>
        <td><span class="badge badge-${p.high_risk?'critical':'low'}">${esc(p.risk_label)}</span></td>
        <td class="mono dim" style="font-size:11px">${esc((p.banner||'').substring(0,60))}</td>
      </tr>`;
    });
    html += `</tbody></table></div>`;
  } else if (nmapPorts.length) {
    html += `<div class="table-wrap"><table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead><tbody>`;
    nmapPorts.forEach(p => { html += `<tr><td class="mono accent">${esc(p.port)}</td><td>${esc(p.protocol)}</td><td>${esc(p.service)}</td><td class="dim">${esc((p.product||'')+' '+(p.version||''))}</td></tr>`; });
    html += `</tbody></table></div>`;
  } else {
    html += `<div class="text-dim">No port data — include "ports" or "nmap" in scan types</div>`;
  }
  html += `</div>`;

  // SSL/TLS
  html += `<div class="tab-content" data-tab="ssl-tab">`;
  if (ssl) {
    const badgeClass = ssl.expired ? 'critical' : ssl.expiring_soon ? 'high' : ssl.valid ? 'low' : 'medium';
    html += `<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">
      <div class="card" style="flex:1;min-width:260px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <div class="card-title">🔐 Certificate Details</div>
          <span class="badge badge-${badgeClass}">${ssl.expired?'EXPIRED':ssl.expiring_soon?'EXPIRING SOON':ssl.valid?'VALID':'UNKNOWN'}</span>
        </div>
        <div class="info-row"><span class="info-label">Common Name</span><span>${esc(ssl.common_name)}</span></div>
        <div class="info-row"><span class="info-label">Issuer</span><span>${esc(ssl.issuer_name)}</span></div>
        <div class="info-row"><span class="info-label">TLS Version</span><span>${esc(ssl.tls_version)}</span></div>
        <div class="info-row"><span class="info-label">Cipher</span><span>${esc(ssl.cipher)}</span></div>
        <div class="info-row"><span class="info-label">Key Bits</span><span>${esc(String(ssl.key_bits||''))}</span></div>
        <div class="info-row"><span class="info-label">Days Remaining</span><span style="color:${ssl.expired?'var(--danger)':ssl.expiring_soon?'orange':'var(--accent)'}">${esc(String(ssl.days_remaining??'—'))}</span></div>
        <div class="info-row"><span class="info-label">SANs</span><span>${esc(String(ssl.sans?.length||0))}</span></div>
        <div class="info-row"><span class="info-label">Wildcards</span><span>${esc(String(ssl.wildcard_count||0))}</span></div>
      </div>
    </div>`;
    if (ssl.notes && ssl.notes.length) {
      ssl.notes.forEach(n => { html += `<div class="alert alert-info" style="font-size:12px;margin-bottom:4px">💡 ${esc(n)}</div>`; });
    }
    if (ssl.sans && ssl.sans.length) {
      html += `<div class="card" style="margin-top:8px"><div class="card-title" style="margin-bottom:8px">Subject Alternative Names (${ssl.sans.length})</div>
        <div style="font-family:monospace;font-size:12px;line-height:1.8;column-count:2">${ssl.sans.map(s=>`<div>${esc(s)}</div>`).join('')}</div></div>`;
    }
  } else {
    html += `<div class="text-dim">SSL scan not run — include "ssl" in scan types</div>`;
  }
  html += `</div>`;

  // Security Headers
  html += `<div class="tab-content" data-tab="headers-tab">`;
  if (headers) {
    const gradeColor = {'A+':'#00d4aa','A':'#00d4aa','B':'#7bc67e','C':'#ffa000','D':'#ff7043','F':'#ff4d4d'}[headers.grade]||'#888';
    html += `<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px;align-items:center">
      <div style="font-size:48px;font-weight:900;color:${gradeColor}">${esc(headers.grade)}</div>
      <div>
        <div style="font-size:14px;font-weight:600">Security Score: ${esc(String(headers.security_score))}/100</div>
        <div style="font-size:12px;color:var(--text-dim)">Headers present: ${esc(String(headers.summary?.present))} / ${esc(String(headers.summary?.total_checked))}</div>
        <div style="font-size:12px;color:var(--text-dim)">Info exposed: ${esc(String(headers.summary?.info_exposed))} headers</div>
      </div>
    </div>`;

    const present = headers.present_headers || {};
    const missing = headers.missing_headers || {};
    const exposed = headers.exposed_info_headers || {};

    if (Object.keys(present).length) {
      html += `<div class="card" style="margin-bottom:8px"><div class="card-title" style="color:var(--accent);margin-bottom:8px">✅ Present Headers (${Object.keys(present).length})</div>`;
      Object.entries(present).forEach(([h, m]) => {
        html += `<div class="info-row"><span class="info-label" style="color:var(--accent)">${esc(h)}</span><span style="font-size:11px;font-family:monospace;max-width:300px;overflow:hidden;text-overflow:ellipsis">${esc(m.value)}</span></div>`;
      });
      html += `</div>`;
    }

    if (Object.keys(missing).length) {
      html += `<div class="card" style="margin-bottom:8px"><div class="card-title" style="color:var(--danger);margin-bottom:8px">❌ Missing Headers (${Object.keys(missing).length})</div>`;
      Object.entries(missing).forEach(([h, m]) => {
        html += `<div class="info-row">
          <span class="info-label">${esc(h)}</span>
          <div style="text-align:right">
            <span class="badge badge-${m.importance==='critical'?'critical':m.importance==='high'?'high':'medium'}">${esc(m.importance)}</span>
            <div style="font-size:10px;color:var(--text-dim);margin-top:2px">${esc(m.recommendation)}</div>
          </div>
        </div>`;
      });
      html += `</div>`;
    }

    if (Object.keys(exposed).length) {
      html += `<div class="card"><div class="card-title" style="color:orange;margin-bottom:8px">⚠️ Information Disclosure</div>`;
      Object.entries(exposed).forEach(([h, m]) => {
        html += `<div class="info-row"><span class="info-label">${esc(h)}</span><span style="color:orange;font-size:12px">${esc(m.value)}</span></div>`;
      });
      html += `</div>`;
    }
  } else {
    html += `<div class="text-dim">Headers scan not run — include "headers" in scan types</div>`;
  }
  html += `</div>`;

  // DNS
  html += `<div class="tab-content" data-tab="dns-tab"><div class="table-wrap"><table><thead><tr><th>Type</th><th>Records</th></tr></thead><tbody>`;
  Object.entries(dns).forEach(([type, vals]) => {
    if (vals && vals.length && type !== 'domain' && type !== 'error') {
      const records = Array.isArray(vals) ? vals.map(v => typeof v === 'object' ? JSON.stringify(v) : v) : [String(vals)];
      html += `<tr><td class="mono accent">${esc(type.toUpperCase())}</td><td class="mono dim">${records.map(r=>esc(r)).join('<br>')}</td></tr>`;
    }
  });
  html += `</tbody></table></div></div>`;

  // OSINT
  const emails = ((osint.emails || {}).emails || []);
  const social = (osint.social || {}).profiles || {};
  html += `<div class="tab-content" data-tab="osint-tab">`;
  if (emails.length) {
    html += `<h4 class="card-title" style="margin-bottom:12px">Emails (${emails.length})</h4><div class="table-wrap"><table><tbody>`;
    emails.forEach(e => { html += `<tr><td class="mono">${esc(e)}</td></tr>`; });
    html += `</tbody></table></div>`;
  }
  if (Object.keys(social).length) {
    html += `<h4 class="card-title" style="margin:16px 0 12px">Social Profiles</h4><div class="table-wrap"><table><thead><tr><th>Platform</th><th>Handles</th></tr></thead><tbody>`;
    Object.entries(social).forEach(([p, h]) => { html += `<tr><td>${esc(p)}</td><td class="mono">${Array.isArray(h)?h.join(', '):esc(String(h))}</td></tr>`; });
    html += `</tbody></table></div>`;
  }
  if (!emails.length && !Object.keys(social).length) {
    html += `<div class="text-dim">No OSINT data — include "osint" in scan types</div>`;
  }
  html += `</div>`;

  html += `<div style="margin-top:20px;display:flex;gap:10px">
    <button class="btn btn-primary" onclick="generateReport('${esc(target)}')">📄 Generate PDF Report</button>
    <button class="btn btn-secondary" onclick="analyzeWithAI('${esc(target)}')">🤖 AI Analysis</button>
  </div>
  <div id="ai-output" style="margin-top:16px"></div>
  <div id="report-output" style="margin-top:16px"></div>`;

  el.innerHTML = html;
  initTabs();
}

window.generateReport = async function(target) {
  const scanId = window._currentScanId || '';
  const btn = event.target;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Generating...';

  const data = await API.post('/api/report', { target, scan_id: scanId });
  btn.disabled = false;
  btn.innerHTML = '📄 Generate PDF Report';

  const out = document.getElementById('report-output');
  if (data.success) {
    out.innerHTML = `<div class="alert alert-success">Report: <a href="/reports/download/${data.filename}" target="_blank">${data.filename}</a></div>`;
  } else {
    out.innerHTML = `<div class="alert alert-error">Report error: ${esc(data.error)}</div>`;
  }
};

window.analyzeWithAI = async function(target) {
  let out = document.getElementById('ai-output');
  if (!out) {
    out = document.createElement('div');
    out.id = 'ai-output';
    out.style.marginTop = '16px';
    const resultsEl = document.getElementById('scan-results');
    if (resultsEl) resultsEl.appendChild(out);
    else document.querySelector('.content')?.appendChild(out);
  }
  out.innerHTML = '<div class="alert alert-info"><span class="spinner"></span> Analyzing with AI...</div>';

  const scanId = window._currentScanId || '';
  let findings = [];
  if (scanId) {
    try {
      const scanData = await API.get(`/api/scan/${scanId}`);
      findings = (scanData.results || {}).vulnerabilities || [];
    } catch (_) {}
  }

  try {
    const data = await API.post('/api/ai/analyze', { findings, target, lang: 'ar' });
    if (data.analysis) {
      out.innerHTML = `<div class="card"><div class="card-header"><div class="card-title">🤖 AI Analysis</div></div>
      <div style="white-space:pre-wrap;font-size:13px;line-height:1.7;color:var(--text)">${esc(data.analysis)}</div></div>`;
    } else {
      out.innerHTML = `<div class="alert alert-error">${esc(data.error || 'AI analysis failed')}</div>`;
    }
  } catch (e) {
    out.innerHTML = `<div class="alert alert-error">AI analysis error: ${esc(e.message)}</div>`;
  }
};

// Target management
window.addTarget = async function() {
  const url = document.getElementById('target-url')?.value?.trim();
  const name = document.getElementById('target-name')?.value?.trim();
  const notes = document.getElementById('target-notes')?.value?.trim();
  if (!url) { toast('URL is required', 'error'); return; }

  const fd = new FormData();
  fd.append('url', url);
  fd.append('name', name || '');
  fd.append('notes', notes || '');

  const r = await fetch('/targets/add', { method: 'POST', body: fd });
  const data = await r.json();
  if (data.success) {
    toast('Target added!');
    setTimeout(() => location.reload(), 800);
  } else {
    toast('Failed to add target', 'error');
  }
};

window.deleteTarget = async function(id) {
  if (!confirm('Remove this target?')) return;
  const data = await API.delete(`/targets/${id}`);
  if (data.success) {
    document.getElementById(`target-row-${id}`)?.remove();
    toast('Target removed');
  }
};

// NLP command bar
window.runNLPCommand = async function(e) {
  if (e && e.key !== 'Enter') return;
  const input = document.getElementById('nlp-input');
  const text = input?.value?.trim();
  if (!text) return;

  const data = await API.post('/api/nlp', { text });
  const action = data.action;
  const target = data.target;

  if (action && action !== 'unknown' && action !== 'error') {
    if (target) {
      const scanTarget = document.getElementById('scan-target');
      if (scanTarget) { scanTarget.value = target; window.location.href = '/scan'; }
    }
    toast(`Command parsed: ${action}${target ? ' → ' + target : ''}`, 'success');
  } else {
    toast('Could not parse command', 'warning');
  }
};

// OSINT page
window.runOSINT = async function() {
  const domain = document.getElementById('osint-domain')?.value?.trim();
  if (!domain) { toast('Enter a domain', 'error'); return; }

  const btn = document.getElementById('osint-btn');
  const out = document.getElementById('osint-output');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Gathering...';
  out.innerHTML = '';

  const data = await API.post('/api/osint', { domain });
  btn.disabled = false;
  btn.innerHTML = '🔍 Gather OSINT';

  const emails = (data.emails || {}).emails || [];
  const relEmails = (data.emails || {}).related_emails || [];
  const social = (data.social || {}).profiles || {};
  const dns = data.dns || {};
  const whois = data.whois || {};
  const subdomains = data.subdomains || [];

  let html = '';

  // DNS Records — always shown when domain is valid
  const dnsEntries = Object.entries(dns).filter(([, v]) => v && v.length);
  if (dnsEntries.length) {
    html += `<div class="card"><div class="card-header"><div class="card-title">🌐 DNS Records</div></div>
    <div class="table-wrap"><table><thead><tr><th>Type</th><th>Records</th></tr></thead><tbody>`;
    dnsEntries.forEach(([type, vals]) => {
      html += `<tr><td class="mono accent">${esc(type)}</td><td class="mono dim">${vals.map(v => esc(v)).join('<br>')}</td></tr>`;
    });
    html += `</tbody></table></div></div>`;
  }

  // WHOIS
  if (whois && !whois.error && (whois.registrar || whois.org)) {
    html += `<div class="card"><div class="card-header"><div class="card-title">📋 WHOIS</div></div>
    <div class="table-wrap"><table><tbody>`;
    const fields = [
      ['Registrar', whois.registrar], ['Org', whois.org], ['Country', whois.country],
      ['Created', whois.creation_date], ['Expires', whois.expiration_date],
      ['Updated', whois.updated_date], ['Name Servers', (whois.name_servers || []).join(', ')],
      ['Status', (whois.status || []).slice(0, 3).join(', ')],
    ];
    fields.filter(([, v]) => v).forEach(([k, v]) => {
      html += `<tr><td style="font-weight:600;width:140px">${k}</td><td class="dim">${esc(v)}</td></tr>`;
    });
    html += `</tbody></table></div></div>`;
  }

  // Subdomains
  if (subdomains.length) {
    html += `<div class="card"><div class="card-header"><div class="card-title">🔎 Subdomains (${subdomains.length})</div></div>
    <div class="table-wrap"><table><thead><tr><th>Subdomain</th><th>IP</th></tr></thead><tbody>`;
    subdomains.slice(0, 50).forEach(s => {
      html += `<tr><td class="mono">${esc(s.subdomain)}</td><td class="mono dim">${esc(s.ip)}</td></tr>`;
    });
    html += `</tbody></table></div></div>`;
  }

  // Emails
  if (emails.length) {
    html += `<div class="card"><div class="card-header"><div class="card-title">📧 Emails Found (${emails.length + relEmails.length})</div></div>
    <div class="table-wrap"><table><tbody>`;
    emails.forEach(e => { html += `<tr><td class="mono">${esc(e)}</td></tr>`; });
    relEmails.slice(0, 10).forEach(e => { html += `<tr><td class="mono dim">${esc(e)}</td></tr>`; });
    html += `</tbody></table></div></div>`;
  }

  // Social Profiles
  if (Object.keys(social).length) {
    html += `<div class="card"><div class="card-header"><div class="card-title">🌐 Social Profiles</div></div>
    <div class="table-wrap"><table><thead><tr><th>Platform</th><th>Handles</th></tr></thead><tbody>`;
    Object.entries(social).forEach(([p, h]) => { html += `<tr><td>${esc(p)}</td><td class="mono">${h.map(v => esc(v)).join(', ')}</td></tr>`; });
    html += `</tbody></table></div></div>`;
  }

  if (!html) html = '<div class="alert alert-warning">No OSINT data found for this domain.</div>';
  out.innerHTML = html;
};

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.addEventListener('DOMContentLoaded', initTabs);
