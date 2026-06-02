(function () {
  'use strict';

  // ---------------------------------------------------------------
  // Static metadata
  // ---------------------------------------------------------------

  const KNOWN_TOOLS = {
    'api.anthropic.com':                  { name: 'Claude / Claude Code',          icon: 'A' },
    'api.openai.com':                     { name: 'OpenAI / ChatGPT',              icon: 'O' },
    'api.githubcopilot.com':              { name: 'GitHub Copilot',                icon: 'G' },
    'copilot-proxy.githubusercontent.com':{ name: 'GitHub Copilot Proxy',          icon: 'G' },
    'generativelanguage.googleapis.com':  { name: 'Google Gemini',                 icon: 'G' },
    'api.mistral.ai':                     { name: 'Mistral',                       icon: 'M' },
    'api.cohere.ai':                      { name: 'Cohere',                        icon: 'C' },
  };

  const TELEMETRY_DOMAINS = [
    'telemetry.anthropic.com',
    'dc.services.visualstudio.com',
    'copilot-telemetry.githubusercontent.com',
    'browser-intake-datadoghq.com',
  ];

  const RECOMMENDATIONS = [
    {
      id: 'proxy-on',
      title: 'Keep proxy enabled',
      check: (cfg) => cfg.proxy.enabled,
      body: 'The proxy must be running for Redactr to intercept and scan traffic. When disabled, AI tools ' +
        'connect directly to their APIs without any PII filtering.'
    },
    {
      id: 'all-layers',
      title: 'Enable all scanning layers',
      check: () => {
        if (!rulesData) return true;
        const layers = ['presidio', 'entropy', 'gliner'];
        return layers.every(layer =>
          rulesData.rules.some(r => r.layer === layer && effectiveEnabled(r.id))
        );
      },
      body: 'Each scanning layer catches different types of sensitive data:<br><br>' +
        '<strong>Regex</strong> — emails, SSNs, API keys, credit cards, JWTs, connection strings<br>' +
        '<strong>Entropy</strong> — high-randomness tokens and secrets that don&apos;t match fixed patterns<br>' +
        '<strong>GLiNER</strong> — ML-based PII detection for names, addresses, and other personal data<br><br>' +
        'Running all layers together provides defense in depth.'
    },
    {
      id: 'sensitive-files',
      title: 'Block sensitive file types',
      check: (cfg) => {
        const exts = cfg.file_blocking.blocked_extensions || [];
        return exts.includes('.env') && exts.includes('.pem');
      },
      body: '<code>.env</code>, <code>.tfstate</code>, <code>.pem</code>, and <code>.key</code> files contain ' +
        'secrets, infrastructure state, and private keys. These should never be transmitted to AI providers.'
    },
    {
      id: 'telemetry',
      title: 'Block telemetry endpoints',
      check: (cfg) => {
        const blocked = (cfg.proxy.blocked_domains || []).map(d => d.toLowerCase());
        return TELEMETRY_DOMAINS.some(t => blocked.includes(t));
      },
      body: 'AI coding tools send telemetry that may include code snippets and file paths. ' +
        'Add these domains to your block list to prevent data collection:<br><br>' +
        '<code>' + TELEMETRY_DOMAINS.join('<br>') + '</code>'
    },
    {
      id: 'safecmd',
      title: 'Restrict AI tool commands',
      check: (cfg) => cfg.hooks.enabled,
      body: 'AI coding tools can execute shell commands on your behalf. The safecmd allowlist restricts ' +
        'them to read-only operations like <code>ls</code>, <code>cat</code>, <code>grep</code>, ' +
        '<code>git status</code>, and <code>git diff</code>. Dangerous commands like <code>rm -rf</code>, ' +
        '<code>git push --force</code>, and <code>chmod</code> are blocked by default.'
    },
    {
      id: 'firewall',
      title: 'Enable OS firewall rules',
      check: () => false,
      body: 'Without firewall rules, AI tools can connect directly to their APIs and bypass the proxy. ' +
        'OS-level firewall rules force all traffic to AI provider domains through Redactr. ' +
        'Run <code>redactr firewall enable</code> to configure this.'
    },
  ];

  const SAMPLE_TEXT =
    "Hi team — please use my work email jane.doe@acme.io and personal phone +1 415 555 0136 " +
    "for follow-up. Production database is postgres://app:p@ssw0rd@db-prod.acme.io:5432/orders. " +
    "AWS access key: AKIAIOSFODNN7EXAMPLE, secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY. " +
    "Card on file 4242 4242 4242 4242, exp 04/27. SSN 123-45-6789. " +
    "GitHub token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789.";

  // ---------------------------------------------------------------
  // State
  // ---------------------------------------------------------------

  const state = {
    config: null,
    stats: null,
    logs: [],
    proxyStatus: null,
    cacheStats: null,
    sessions: { supported: true, sessions: [], proxy_addr: '', note: '' },
    sessionsError: null,
    sessionsBackoffMs: 3000,
    sessionsTimer: null,
    ws: null,
    wsConnected: false,
    activeTab: 'overview',
    logFilter: { provider: '', status: '', search: '' },
  };

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // ---------------------------------------------------------------
  // API
  // ---------------------------------------------------------------

  async function api(path, opts) {
    const res = await fetch('/api' + path, opts);
    if (!res.ok) throw new Error(await res.text());
    const ct = res.headers.get('content-type') || '';
    return ct.includes('application/json') ? res.json() : res.text();
  }

  async function fetchAll() {
    const endpoints = [
      ['config',      '/config'],
      ['stats',       '/stats'],
      ['logs',        '/logs?limit=200'],
      ['proxyStatus', '/proxy/status'],
      ['cacheStats',  '/cache/stats'],
    ];
    const results = await Promise.allSettled(endpoints.map(([, path]) => api(path)));

    const failed = [];
    results.forEach((res, i) => {
      const [key] = endpoints[i];
      if (res.status === 'fulfilled') {
        if (key === 'logs') state.logs = res.value || [];
        else state[key] = res.value;
      } else {
        failed.push({ key, path: endpoints[i][1], err: res.reason });
        console.error(`[redactr] ${endpoints[i][1]} failed:`, res.reason);
      }
    });

    render();

    if (failed.length === endpoints.length) {
      toast('Cannot reach the API — is the server running?', 'error');
    } else if (failed.length > 0) {
      const names = failed.map(f => f.path).join(', ');
      toast(`Some endpoints failed: ${names}`, 'warn');
    }
  }

  // ---------------------------------------------------------------
  // WebSocket — live scan stream
  // ---------------------------------------------------------------

  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = proto + '//' + location.host + '/api/ws';
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (_) {
      setLive(false);
      setTimeout(connectWS, 3000);
      return;
    }

    ws.onopen = () => setLive(true);
    ws.onmessage = (e) => {
      try {
        const report = JSON.parse(e.data);
        state.logs.unshift(report);
        if (state.logs.length > 200) state.logs.pop();
        renderMetricsBadge();
        if (state.activeTab === 'logs') renderLogs();
        if (state.activeTab === 'overview') {
          renderRecent();
          renderSparklines();
          renderChart();
        }
      } catch (_) {}
    };
    ws.onclose = () => {
      setLive(false);
      setTimeout(connectWS, 3000);
    };
    ws.onerror = () => { try { ws.close(); } catch (_) {} };
    state.ws = ws;
  }

  function setLive(on) {
    state.wsConnected = on;
    const pill = $('#live-pill');
    const label = $('#live-label');
    if (!pill) return;
    pill.dataset.state = on ? 'on' : 'off';
    label.textContent = on ? 'Live stream connected' : 'Disconnected';
  }

  // ---------------------------------------------------------------
  // Tabs
  // ---------------------------------------------------------------

  const TAB_TITLES = {
    overview: 'Overview',
    logs: 'Scan Logs',
    sessions: 'Sessions',
    testscan: 'Test Scan',
    config: 'Configuration',
  };

  function setTab(name) {
    state.activeTab = name;
    $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    $$('.tab-content').forEach(s => s.classList.toggle('active', s.id === name));
    $('#page-title').textContent = TAB_TITLES[name] || 'Overview';
    if (name === 'sessions') {
      pollSessions();
      startSessionsPoller();
    } else {
      stopSessionsPoller();
    }
  }

  function initTabs() {
    $$('.nav-item').forEach(btn => {
      btn.addEventListener('click', () => setTab(btn.dataset.tab));
    });
    $$('[data-jump]').forEach(el => {
      el.addEventListener('click', () => setTab(el.dataset.jump));
    });
  }

  // ---------------------------------------------------------------
  // Render — orchestrator
  // ---------------------------------------------------------------

  function render() {
    renderProxy();
    renderHero();
    renderMetrics();
    renderSparklines();
    renderChart();
    renderTools();
    renderRecommendations();
    renderRecent();
    renderLogProviders();
    renderLogs();
    renderConfig();
    renderCacheStats();
    renderMetricsBadge();
    renderFooter();
  }

  // ---------------------------------------------------------------
  // Proxy header
  // ---------------------------------------------------------------

  function renderProxy() {
    const pill = $('#proxy-pill');
    const label = $('#proxy-label');
    const addr = $('#proxy-addr');
    const btn = $('#proxy-toggle');
    const btnLabel = $('#proxy-btn-label');
    if (!pill || !state.proxyStatus) return;

    const enabled = !!state.proxyStatus.enabled;
    const routing = state.proxyStatus.routing === true;

    let visual = 'off';
    let labelText = 'Proxy offline';
    if (enabled && routing) {
      visual = 'on';
      labelText = 'Proxy active';
    } else if (enabled && !routing) {
      visual = 'listening';
      labelText = 'Listening — routing not installed';
    }

    pill.dataset.state = visual;
    if (label) label.textContent = labelText;
    if (addr) addr.textContent = state.proxyStatus.addr || '';
    if (btnLabel) btnLabel.textContent = enabled ? 'Disable proxy' : 'Enable proxy';
    if (btn) {
      btn.classList.toggle('btn-primary', !enabled);
      btn.classList.toggle('btn-ghost', enabled);
    }
  }

  function renderFooter() {
    const addr = state.proxyStatus && state.proxyStatus.addr;
    $('#footer-addr').textContent = addr || location.host || '—';
  }

  // ---------------------------------------------------------------
  // Hero / posture row
  // ---------------------------------------------------------------

  function renderHero() {
    if (!state.config) return;
    const c = state.config;
    const cs = state.cacheStats || {};
    const allLayers = ['presidio', 'entropy', 'gliner'];
    const layersOn = rulesData
      ? allLayers.filter(layer =>
          rulesData.rules.some(r => r.layer === layer && effectiveEnabled(r.id))
        )
      : allLayers;

    const hits = cs.hits || 0;
    const misses = cs.misses || 0;
    const total = hits + misses;
    const rate = total > 0 ? Math.round((hits / total) * 100) + '%' : '—';

    $('#hero-cache-rate').textContent = rate;
    $('#hero-cache-size').textContent = fmt(cs.size || 0);
    $('#hero-layers').textContent = layersOn.length + ' / 3';

    const proxyOn = state.proxyStatus && state.proxyStatus.enabled;
    let headline, sub;
    if (!proxyOn) {
      headline = 'Proxy is offline';
      sub = 'Enable the proxy from the top right to begin inspecting requests to AI providers.';
    } else if (layersOn.length === 0) {
      headline = 'Proxy is up — but no scanning layers are active';
      sub = 'Traffic is being intercepted, but nothing is being scanned. Enable at least one layer in Configuration.';
    } else if (layersOn.length < 3) {
      headline = `Operating with ${layersOn.length} of 3 scanning layers`;
      sub = 'For defense in depth, enable regex, entropy, and the GLiNER ML model together.';
    } else {
      headline = 'All scanning layers active';
      sub = 'Requests passing through the proxy are inspected by regex, entropy, and ML pipelines before being forwarded.';
    }
    $('#hero-headline').textContent = headline;
    $('#hero-sub').textContent = sub;
  }

  // ---------------------------------------------------------------
  // Stat cards
  // ---------------------------------------------------------------

  function renderMetrics() {
    const s = state.stats || {};
    $('#m-scanned').textContent = fmt(s.total_scanned || 0);
    $('#m-redacted').textContent = fmt(s.total_redactions || 0);
    $('#m-blocked').textContent = fmt(s.total_blocked || 0);
    $('#m-latency').innerHTML = (s.avg_latency_ms || 0).toFixed(1) + '<span class="stat-unit">ms</span>';

    // Trend pills derived from recent log halves
    const halves = halfBuckets(state.logs);
    setTrend('#trend-scanned', halves.recent.scanned, halves.older.scanned);
    setTrend('#trend-redacted', halves.recent.redacted, halves.older.redacted);
    setTrend('#trend-blocked', halves.recent.blocked, halves.older.blocked);
  }

  function renderMetricsBadge() {
    $('#nav-log-count').textContent = state.logs.length > 99 ? '99+' : String(state.logs.length);
  }

  function halfBuckets(logs) {
    const sorted = [...logs].sort((a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
    const half = Math.ceil(sorted.length / 2);
    const recent = sorted.slice(0, half);
    const older = sorted.slice(half);
    const tally = (arr) => arr.reduce((acc, l) => {
      acc.scanned++;
      if (l.redactions && l.redactions.length > 0) acc.redacted++;
      if (l.blocked) acc.blocked++;
      return acc;
    }, { scanned: 0, redacted: 0, blocked: 0 });
    return { recent: tally(recent), older: tally(older) };
  }

  function setTrend(sel, recent, older) {
    const el = $(sel);
    if (!el) return;
    el.classList.remove('up', 'down');
    if (recent === 0 && older === 0) {
      el.textContent = '—';
      return;
    }
    if (older === 0) {
      el.textContent = '+' + fmt(recent);
      el.classList.add('up');
      return;
    }
    const pct = Math.round(((recent - older) / older) * 100);
    if (pct === 0) { el.textContent = '0%'; return; }
    el.textContent = (pct > 0 ? '+' : '') + pct + '%';
    el.classList.add(pct > 0 ? 'up' : 'down');
  }

  // ---------------------------------------------------------------
  // Sparklines (24 hourly buckets)
  // ---------------------------------------------------------------

  function renderSparklines() {
    const buckets = hourlyBuckets(state.logs, 24);
    drawSparkline('#spark-scanned',  buckets.map(b => b.scanned),  '#34d399');
    drawSparkline('#spark-redacted', buckets.map(b => b.redacted), '#fbbf24');
    drawSparkline('#spark-blocked',  buckets.map(b => b.blocked),  '#f87171');
    drawSparkline('#spark-latency',  buckets.map(b => b.avgLatency), '#60a5fa');
  }

  function hourlyBuckets(logs, count) {
    const now = Date.now();
    const bucketMs = 3600000;
    const buckets = Array.from({ length: count }, () => ({ scanned: 0, redacted: 0, blocked: 0, latencyTotal: 0, avgLatency: 0 }));
    logs.forEach(log => {
      const t = new Date(log.timestamp).getTime();
      const idx = count - 1 - Math.floor((now - t) / bucketMs);
      if (idx >= 0 && idx < count) {
        const b = buckets[idx];
        b.scanned++;
        b.latencyTotal += (log.latency_ms || 0);
        if (log.redactions && log.redactions.length > 0) b.redacted++;
        if (log.blocked) b.blocked++;
      }
    });
    buckets.forEach(b => { b.avgLatency = b.scanned ? b.latencyTotal / b.scanned : 0; });
    return buckets;
  }

  function drawSparkline(sel, data, color) {
    const svg = $(sel);
    if (!svg) return;
    if (!data.some(v => v > 0)) {
      svg.innerHTML = `<line x1="0" y1="14" x2="100" y2="14" stroke="#1f242c" stroke-width="1" stroke-dasharray="2 3"/>`;
      return;
    }
    const max = Math.max(...data, 1);
    const w = 100, h = 28;
    const pts = data.map((v, i) => {
      const x = (i / (data.length - 1)) * w;
      const y = h - 2 - (v / max) * (h - 4);
      return [x, y];
    });
    const linePath = pts.map((p, i) => (i === 0 ? 'M' : 'L') + p[0].toFixed(2) + ' ' + p[1].toFixed(2)).join(' ');
    const areaPath = linePath + ` L${w} ${h} L0 ${h} Z`;
    svg.innerHTML =
      `<path d="${areaPath}" fill="${color}" fill-opacity="0.10"/>` +
      `<path d="${linePath}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>`;
  }

  // ---------------------------------------------------------------
  // Trend chart (full chart on overview)
  // ---------------------------------------------------------------

  function renderChart() {
    const svg = $('#trend-chart');
    if (!svg) return;
    if (!state.logs.length) {
      svg.innerHTML = `
        <text x="300" y="105" text-anchor="middle" fill="#5a616d" font-size="13" font-family="Geist, sans-serif">
          No scan activity yet
        </text>
        <text x="300" y="125" text-anchor="middle" fill="#3f4651" font-size="11" font-family="Geist, sans-serif">
          Send a request through the proxy or run a Test Scan to populate this chart
        </text>`;
      return;
    }

    const buckets = hourlyBuckets(state.logs, 24);
    const maxVal = Math.max(1, ...buckets.map(b => b.scanned));
    const w = 600, h = 220, px = 36, py = 18;
    const cw = w - px * 2, ch = h - py * 2 - 14;

    function path(values, color) {
      const linePts = values.map((v, i) => {
        const x = px + (i / (buckets.length - 1)) * cw;
        const y = py + ch - (v / maxVal) * ch;
        return [x, y];
      });
      const line = linePts.map((p, i) => (i === 0 ? 'M' : 'L') + p[0].toFixed(2) + ' ' + p[1].toFixed(2)).join(' ');
      const area = line + ` L${px + cw} ${py + ch} L${px} ${py + ch} Z`;
      const dots = values.map((v, i) => {
        if (v === 0) return '';
        const [x, y] = linePts[i];
        return `<circle cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="2.5" fill="${color}" stroke="#12151b" stroke-width="1.5"/>`;
      }).join('');
      return `
        <path d="${area}" fill="${color}" fill-opacity="0.07"/>
        <path d="${line}" fill="none" stroke="${color}" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"/>
        ${dots}`;
    }

    let grid = '';
    const steps = 4;
    for (let i = 0; i <= steps; i++) {
      const y = py + (i / steps) * ch;
      const v = Math.round(maxVal * (1 - i / steps));
      grid += `<line x1="${px}" y1="${y}" x2="${px + cw}" y2="${y}" stroke="#171b22" stroke-width="1"/>`;
      grid += `<text x="${px - 8}" y="${y + 4}" text-anchor="end" fill="#4b5563" font-size="10" font-family="Geist Mono, monospace">${v}</text>`;
    }

    let timeLabels = '';
    [0, 6, 12, 18, 23].forEach(i => {
      const x = px + (i / (buckets.length - 1)) * cw;
      const hrs = buckets.length - 1 - i;
      timeLabels += `<text x="${x}" y="${h - 4}" text-anchor="middle" fill="#4b5563" font-size="10" font-family="Geist Mono, monospace">${hrs === 0 ? 'now' : hrs + 'h'}</text>`;
    });

    svg.innerHTML =
      grid + timeLabels +
      path(buckets.map(b => b.scanned),  '#34d399') +
      path(buckets.map(b => b.redacted), '#fbbf24') +
      path(buckets.map(b => b.blocked),  '#f87171');
  }

  // ---------------------------------------------------------------
  // Tools list
  // ---------------------------------------------------------------

  function renderTools() {
    const el = $('#tools-list');
    if (!el || !state.config) return;
    const intercepted = new Set((state.config.proxy.intercepted_domains || []).map(d => d.toLowerCase()));
    const blocked = new Set((state.config.proxy.blocked_domains || []).map(d => d.toLowerCase()));
    const allDomains = new Set([...Object.keys(KNOWN_TOOLS), ...intercepted, ...blocked]);

    if (allDomains.size === 0) {
      el.innerHTML = '<div class="empty-state" style="padding:24px"><p>No domains configured.</p></div>';
      return;
    }

    const sorted = Array.from(allDomains).sort();
    el.innerHTML = sorted.map(domain => {
      const tool = KNOWN_TOOLS[domain] || { name: domain, icon: domain[0].toUpperCase() };
      let badge, badgeClass;
      if (blocked.has(domain)) { badge = 'Blocked'; badgeClass = 'badge-blocked'; }
      else if (intercepted.has(domain)) { badge = 'Scanning'; badgeClass = 'badge-intercept'; }
      else { badge = 'Idle'; badgeClass = 'badge-inactive'; }
      return `
        <div class="tool-item">
          <div class="tool-avatar">${esc(tool.icon)}</div>
          <div class="tool-info">
            <span class="tool-name">${esc(tool.name)}</span>
            <span class="tool-domain">${esc(domain)}</span>
          </div>
          <span class="tool-badge ${badgeClass}">${badge}</span>
        </div>`;
    }).join('');
  }

  // ---------------------------------------------------------------
  // Recommendations
  // ---------------------------------------------------------------

  function renderRecommendations() {
    const el = $('#recommendations');
    if (!el || !state.config) return;

    const evaluated = RECOMMENDATIONS.map(r => ({ ...r, ok: r.check(state.config) }));
    const okCount = evaluated.filter(r => r.ok).length;
    $('#rec-summary').textContent = `${okCount} / ${evaluated.length} passing`;

    el.innerHTML = evaluated.map(rec => `
      <div class="rec-item ${rec.ok ? 'ok' : 'warn'}" data-rec="${rec.id}">
        <div class="rec-header">
          <span class="rec-check">${rec.ok ? '✓' : '!'}</span>
          <span class="rec-title">${esc(rec.title)}</span>
          <span class="rec-status">${rec.ok ? 'OK' : 'Action'}</span>
          <span class="rec-chevron">▾</span>
        </div>
        <div class="rec-body">${rec.body}</div>
      </div>`).join('');

    el.querySelectorAll('.rec-header').forEach(h =>
      h.addEventListener('click', () => h.parentElement.classList.toggle('open'))
    );
  }

  // ---------------------------------------------------------------
  // Recent activity
  // ---------------------------------------------------------------

  function renderRecent() {
    const el = $('#recent-list');
    if (!el) return;
    if (!state.logs.length) {
      el.innerHTML = `
        <div class="empty-state" style="padding:24px 0">
          <div class="empty-state-mark">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 6v6l4 2"/><circle cx="12" cy="12" r="9"/></svg>
          </div>
          <h3>No activity yet</h3>
          <p>Live scan reports will appear here as they happen.</p>
        </div>`;
      return;
    }
    el.innerHTML = state.logs.slice(0, 8).map(log => {
      const t = new Date(log.timestamp);
      const time = t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const status = log.blocked ? 'blocked' : ((log.redactions || []).length > 0 ? 'redacted' : 'clean');
      return `
        <div class="recent-item">
          <span class="recent-time">${time}</span>
          <span class="recent-provider">${esc(log.provider || 'unknown')}</span>
          <span class="recent-status ${status}">${status}</span>
        </div>`;
    }).join('');
  }

  // ---------------------------------------------------------------
  // Logs tab
  // ---------------------------------------------------------------

  function renderLogProviders() {
    const select = $('#log-filter-provider');
    if (!select) return;
    const providers = new Set(state.logs.map(l => l.provider).filter(Boolean));
    const cur = new Set(Array.from(select.options).map(o => o.value));
    providers.forEach(p => {
      if (!cur.has(p)) {
        const opt = document.createElement('option');
        opt.value = p;
        opt.textContent = p;
        select.appendChild(opt);
      }
    });
  }

  function renderLogs() {
    const el = $('#log-list');
    if (!el) return;

    const f = state.logFilter;
    let filtered = state.logs;
    if (f.provider) filtered = filtered.filter(l => l.provider === f.provider);
    if (f.status) {
      filtered = filtered.filter(l => {
        const status = l.blocked ? 'blocked' : ((l.redactions || []).length > 0 ? 'redacted' : 'clean');
        return status === f.status;
      });
    }
    if (f.search) {
      const q = f.search.toLowerCase();
      filtered = filtered.filter(l => {
        if ((l.provider || '').toLowerCase().includes(q)) return true;
        if ((l.reason || '').toLowerCase().includes(q)) return true;
        return (l.redactions || []).some(r =>
          (r.label || '').toLowerCase().includes(q) ||
          (r.original || '').toLowerCase().includes(q)
        );
      });
    }

    if (!filtered.length) {
      el.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-mark">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 6h16M4 12h16M4 18h10"/></svg>
          </div>
          <h3>${state.logs.length === 0 ? 'No scan logs yet' : 'No matches for current filters'}</h3>
          <p>${state.logs.length === 0
            ? 'Enable the proxy and send a request through Claude, ChatGPT, or Copilot — or use the Test Scan tab to verify the pipeline.'
            : 'Try clearing the search or status filter to see more results.'}</p>
        </div>`;
      return;
    }

    el.innerHTML = filtered.slice(0, 100).map(log => {
      const t = new Date(log.timestamp);
      const time = t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      const date = t.toLocaleDateString([], { month: 'short', day: 'numeric' });

      const redCount = (log.redactions || []).length;
      const status = log.blocked ? { cls: 'status-blocked', text: 'Blocked' }
                  : redCount > 0 ? { cls: 'status-redacted', text: 'Redacted' }
                                 : { cls: 'status-clean', text: 'Clean' };

      let detail = '';
      if (redCount > 0) {
        detail += `<div class="log-detail-section"><h4>Redactions (${redCount})</h4><div class="redaction-list">`;
        log.redactions.forEach(r => {
          const masked = r.original ? r.original.substring(0, 3) + '•••' : '•••';
          detail += `
            <div class="redaction-item">
              <span class="redaction-label">${esc(r.label)}</span>
              <span class="redaction-value">${esc(masked)}</span>
              <span class="redaction-pos">${r.start}–${r.end}</span>
              <span class="redaction-layer">${esc(r.layer || '—')}</span>
            </div>`;
        });
        detail += '</div></div>';
      }

      if (log.layers && log.layers.length) {
        detail += `<div class="log-detail-section"><h4>Scanning layers</h4><div class="layer-list">`;
        log.layers.forEach(l => {
          detail += `
            <span class="layer-tag">
              <span class="layer-tag-name">${esc(l.name)}</span>
              <span class="layer-tag-findings">${l.findings_count}</span>
              <span class="layer-tag-latency">${l.latency_ms}ms</span>
            </span>`;
        });
        detail += '</div></div>';
      }

      if (log.reason) {
        detail += `<div class="log-detail-section"><h4>Reason</h4><p style="font-size:12px;color:var(--text-3);line-height:1.6">${esc(log.reason)}</p></div>`;
      }

      if (!detail) {
        detail = `<div class="log-detail-section"><p style="font-size:12px;color:var(--text-4);padding:8px 0">No findings recorded for this scan.</p></div>`;
      }

      return `
        <div class="log-entry">
          <div class="log-summary">
            <span class="log-time"><span class="log-date">${date}</span> ${time}</span>
            <span class="log-provider">${esc(log.provider || 'unknown')}</span>
            <span class="log-status ${status.cls}">${status.text}</span>
            <span class="log-latency">${log.latency_ms ?? 0}ms</span>
            <span class="log-count ${redCount === 0 ? 'zero' : ''}">${redCount > 0 ? redCount + ' found' : '—'}</span>
            <span class="log-chevron">▾</span>
          </div>
          <div class="log-detail">${detail}</div>
        </div>`;
    }).join('');

    el.querySelectorAll('.log-summary').forEach(s =>
      s.addEventListener('click', () => s.parentElement.classList.toggle('open'))
    );
  }

  // ---------------------------------------------------------------
  // Config
  // ---------------------------------------------------------------

  function renderConfig() {
    if (!state.config) return;
    const c = state.config;
    $('#cfg-entropy-thresh').value = c.scanning.entropy_threshold;
    $('#cfg-intercept').value = (c.proxy.intercepted_domains || []).join('\n');
    $('#cfg-blocked-domains').value = (c.proxy.blocked_domains || []).join('\n');
    $('#cfg-extensions').value = (c.file_blocking.blocked_extensions || []).join('\n');
    $('#cfg-hooks').checked = c.hooks.enabled;
    $('#cfg-claude-hooks').checked = c.hooks.claude_code;
    $('#cfg-cache-size').value = c.scanning.cache_max_size;
  }

  function renderCacheStats() {
    const cs = state.cacheStats || {};
    $('#cache-hits').textContent = fmt(cs.hits || 0);
    $('#cache-misses').textContent = fmt(cs.misses || 0);
    $('#cache-size').textContent = fmt(cs.size || 0);
  }

  // ---------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------

  function initActions() {
    $('#proxy-toggle').addEventListener('click', async () => {
      const on = state.proxyStatus && state.proxyStatus.enabled;
      try {
        const res = await api(on ? '/proxy/disable' : '/proxy/enable', { method: 'POST' });
        if (!on) {
          if (res && res.routing === 'failed') {
            toast('Listening, but routing failed: ' + (res.reason || 'unknown'), 'warn');
          } else {
            toast('Proxy enabled', 'ok');
          }
        } else {
          toast('Proxy disabled', 'warn');
        }
        await fetchAll();
      } catch (err) {
        toast('Could not toggle proxy: ' + err.message, 'error');
      }
    });

    $('#config-save').addEventListener('click', async () => {
      const lines = (id) => $('#' + id).value.split('\n').map(s => s.trim()).filter(Boolean);
      const cfg = {
        proxy: {
          enabled: state.config.proxy.enabled,
          intercepted_domains: lines('cfg-intercept'),
          blocked_domains: lines('cfg-blocked-domains'),
        },
        scanning: {
          entropy_threshold: parseFloat($('#cfg-entropy-thresh').value) || 4.5,
          custom_patterns: state.config.scanning.custom_patterns || [],
          custom_blocked_words: state.config.scanning.custom_blocked_words || [],
          cache_max_size: parseInt($('#cfg-cache-size').value) || 10000,
        },
        file_blocking: {
          blocked_extensions: lines('cfg-extensions'),
          content_patterns_enabled: state.config.file_blocking.content_patterns_enabled,
        },
        hooks: {
          enabled: $('#cfg-hooks').checked,
          claude_code: $('#cfg-claude-hooks').checked,
          safecmd_overrides: state.config.hooks.safecmd_overrides || { added: [], removed: [] },
        },
        mcp: state.config.mcp || { wrapped_servers: {} },
      };
      try {
        await api('/config', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(cfg),
        });
        toast('Configuration saved', 'ok');
        await fetchAll();
      } catch (err) {
        toast('Save failed: ' + err.message, 'error');
      }
    });

    $('#cache-clear').addEventListener('click', async () => {
      try {
        await api('/cache/clear', { method: 'POST' });
        toast('Cache cleared', 'ok');
        await fetchAll();
      } catch (err) {
        toast('Could not clear cache', 'error');
      }
    });

    $('#log-refresh').addEventListener('click', fetchAll);

    $('#log-filter-provider').addEventListener('change', (e) => {
      state.logFilter.provider = e.target.value;
      renderLogs();
    });
    $('#log-filter-status').addEventListener('change', (e) => {
      state.logFilter.status = e.target.value;
      renderLogs();
    });
    $('#log-search').addEventListener('input', (e) => {
      state.logFilter.search = e.target.value;
      renderLogs();
    });

    $('#ts-sample').addEventListener('click', () => {
      $('#ts-input').value = SAMPLE_TEXT;
    });

    $('#ts-run').addEventListener('click', runTestScan);
  }

  // ---------------------------------------------------------------
  // Test Scan
  // ---------------------------------------------------------------

  async function runTestScan() {
    const input = $('#ts-input').value;
    if (!input.trim()) {
      toast('Enter some text to scan', 'warn');
      return;
    }
    const btn = $('#ts-run');
    btn.disabled = true;
    const originalLabel = btn.innerHTML;
    btn.innerHTML = '<span class="btn-dot"></span>Scanning…';

    const start = performance.now();
    try {
      const result = await api('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: input }),
      });
      const elapsed = (performance.now() - start).toFixed(0);
      renderTestScan(result, elapsed);
    } catch (err) {
      toast('Scan failed: ' + err.message, 'error');
      $('#ts-output').innerHTML = `<div class="empty-pane" style="color:var(--danger)"><span>Error: ${esc(err.message)}</span></div>`;
    } finally {
      btn.disabled = false;
      btn.innerHTML = originalLabel;
    }
  }

  function renderTestScan(result, elapsed) {
    const findings = result.findings || [];
    const meta = $('#ts-result-meta');
    meta.textContent = `${findings.length} finding${findings.length === 1 ? '' : 's'} • ${elapsed}ms`;

    const out = $('#ts-output');
    if (findings.length === 0) {
      out.innerHTML = `<div style="color:var(--accent)">No PII detected.</div><div style="margin-top:10px;color:var(--text-2)">${esc(result.original || '')}</div>`;
    } else {
      out.innerHTML = highlightFindings(result.original || '', findings);
    }

    const findingsEl = $('#ts-findings');
    if (findings.length === 0) {
      findingsEl.innerHTML = '';
      return;
    }
    findingsEl.innerHTML = findings.map(f => `
      <div class="redaction-item">
        <span class="redaction-label">${esc(f.label)}</span>
        <span class="redaction-value">${esc(f.value || '')}</span>
        <span class="redaction-pos">${f.start}–${f.end}</span>
        <span class="redaction-layer">${esc(f.layer || '—')}</span>
      </div>`).join('');
  }

  function highlightFindings(text, findings) {
    if (!text || !findings.length) return esc(text);
    const sorted = [...findings].sort((a, b) => a.start - b.start);
    let out = '';
    let cursor = 0;
    sorted.forEach(f => {
      if (f.start < cursor) return;
      out += esc(text.slice(cursor, f.start));
      out += `<mark>${esc(text.slice(f.start, f.end))}</mark>`;
      cursor = f.end;
    });
    out += esc(text.slice(cursor));
    return out;
  }

  // ---------------------------------------------------------------
  // Toasts
  // ---------------------------------------------------------------

  function toast(message, kind) {
    const stack = $('#toasts');
    const el = document.createElement('div');
    el.className = 'toast ' + (kind === 'error' ? 'error' : kind === 'warn' ? 'warn' : '');
    const sticky = kind === 'error' || kind === 'warn';
    el.innerHTML = `
      <span class="toast-dot"></span>
      <span class="toast-msg">${esc(message)}</span>
      ${sticky ? `<button class="toast-close" aria-label="Dismiss">×</button>` : ''}
    `;
    stack.appendChild(el);

    const dismiss = () => {
      el.classList.add('leaving');
      setTimeout(() => el.remove(), 180);
    };
    if (sticky) {
      // Errors/warnings: persist until user dismisses. Click anywhere on the
      // toast (or the × button) to close.
      el.addEventListener('click', dismiss);
    } else {
      // ok/info toasts auto-dismiss.
      setTimeout(dismiss, 2800);
    }
  }

  // ---------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------

  function fmt(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return String(n);
  }

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  // ---------------------------------------------------------------
  // Sessions — polling + render + actions
  // ---------------------------------------------------------------

  function startSessionsPoller() {
    if (state.sessionsTimer) return;
    const tick = async () => {
      await pollSessions();
      // Backoff up to 30s on persistent failure, reset on success.
      const next = state.sessionsError
        ? Math.min(state.sessionsBackoffMs * 1.6, 30000)
        : 3000;
      state.sessionsBackoffMs = next;
      if (state.activeTab === 'sessions') {
        state.sessionsTimer = setTimeout(tick, next);
      }
    };
    state.sessionsTimer = setTimeout(tick, 3000);
  }

  function stopSessionsPoller() {
    if (state.sessionsTimer) {
      clearTimeout(state.sessionsTimer);
      state.sessionsTimer = null;
    }
    state.sessionsBackoffMs = 3000;
  }

  async function pollSessions() {
    try {
      const r = await api('/sessions');
      state.sessions = r;
      state.sessionsError = null;
    } catch (err) {
      state.sessionsError = err.message || String(err);
      console.error('[redactr] /sessions failed:', err);
    }
    renderSessions();
    renderRunawayBadge();
  }

  function renderRunawayBadge() {
    const badge = $('#nav-runaway-count');
    if (!badge) return;
    const count = (state.sessions.sessions || []).filter(s => s.status === 'runaway').length;
    if (count > 0) {
      badge.textContent = String(count);
      badge.hidden = false;
      badge.classList.add('badge-danger');
    } else {
      badge.hidden = true;
      badge.classList.remove('badge-danger');
    }
  }

  function renderSessions() {
    const list = $('#session-list');
    const summary = $('#sessions-summary');
    if (!list) return;

    if (state.sessions && state.sessions.supported === false) {
      summary.innerHTML = '';
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-mark">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>
          </div>
          <h3>Session discovery isn’t available on this OS</h3>
          <p>${esc(state.sessions.note || 'Currently macOS-only. Run `redactr shell` from a terminal to launch a protected shell manually.')}</p>
        </div>`;
      return;
    }

    if (state.sessionsError) {
      summary.innerHTML = '';
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-mark" style="color:var(--danger)">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>
          </div>
          <h3>Could not list sessions</h3>
          <p>${esc(state.sessionsError)}</p>
        </div>`;
      return;
    }

    const sessions = state.sessions.sessions || [];
    const protectedCount = sessions.filter(s => s.status === 'protected').length;
    const runawayCount   = sessions.filter(s => s.status === 'runaway').length;
    const unknownCount   = sessions.filter(s => s.status === 'unknown').length;

    summary.innerHTML = `
      <div class="sessions-summary-pill" data-tone="primary"><span class="dot"></span><strong>${protectedCount}</strong> protected</div>
      <div class="sessions-summary-pill" data-tone="danger"><span class="dot"></span><strong>${runawayCount}</strong> runaway</div>
      <div class="sessions-summary-pill" data-tone="muted"><span class="dot"></span><strong>${unknownCount}</strong> idle</div>
      <span class="sessions-summary-meta">via ${esc(state.sessions.proxy_addr || '—')}</span>`;

    if (sessions.length === 0) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-mark">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M7 20h10"/></svg>
          </div>
          <h3>No AI tool sessions detected</h3>
          <p>Open <em>Claude Code</em>, <em>Codex</em>, <em>Cursor</em> or another AI tool — sessions appear here within a few seconds.</p>
        </div>`;
      return;
    }

    list.innerHTML = sessions.map(renderSessionCard).join('');
    list.querySelectorAll('[data-action]').forEach(btn => {
      btn.addEventListener('click', onSessionAction);
    });
  }

  function renderSessionCard(s) {
    const status = s.status;
    const since = s.started_at ? timeAgo(new Date(s.started_at)) : 'unknown';
    const evidence = [];

    if (s.bound_flag) evidence.push({ tone: 'ok', text: 'REDACTR_BOUND=1' });
    if (s.has_proxy_env) evidence.push({ tone: 'ok', text: 'HTTPS_PROXY → ' + (s.proxy_env || '?') });
    if (s.via_proxy) evidence.push({ tone: 'ok', text: 'TCP → Redactr proxy' });
    (s.direct_ai_conn || []).forEach(c => evidence.push({ tone: 'bad', text: 'direct → ' + c }));
    if (!s.has_proxy_env && !s.bound_flag && !s.via_proxy && (s.direct_ai_conn || []).length === 0) {
      evidence.push({ tone: 'muted', text: 'no AI traffic observed' });
    }

    return `
      <article class="session-card" data-status="${status}">
        <header class="session-head">
          <div class="session-head-left">
            <div class="session-tool-mark">${esc((s.tool || '?')[0])}</div>
            <div class="session-id">
              <div class="session-tool-name">${esc(s.tool || 'Unknown tool')}</div>
              <div class="session-meta-line">
                <span class="session-pid">PID ${s.pid}</span>
                <span class="session-sep">·</span>
                <span class="session-user">${esc(s.user || '')}</span>
                <span class="session-sep">·</span>
                <span class="session-started">${since}</span>
              </div>
            </div>
          </div>
          <div class="session-status-pill" data-status="${status}">
            <span class="session-status-dot"></span>
            ${status === 'protected' ? 'Protected'
              : status === 'runaway' ? 'Runaway'
              : 'Idle'}
          </div>
        </header>

        <p class="session-reason">${esc(s.reason || '')}</p>

        <div class="session-evidence">
          ${evidence.map(e => `<span class="ev-chip ev-${e.tone}">${esc(e.text)}</span>`).join('')}
        </div>

        <div class="session-cmd" title="${esc(s.command || '')}">${esc(s.command || '')}</div>

        <div class="session-actions">
          ${status === 'runaway' ? `
            <button class="btn btn-primary btn-sm" data-action="rebind" data-pid="${s.pid}">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg>
              Stop &amp; reopen protected
            </button>` : ''}
          ${status === 'runaway' ? `
            <button class="btn btn-ghost btn-sm" data-action="stop" data-pid="${s.pid}">Stop</button>
          ` : ''}
          ${status !== 'runaway' ? `
            <button class="btn btn-ghost btn-sm" data-action="stop" data-pid="${s.pid}">Stop</button>
          ` : ''}
        </div>
      </article>`;
  }

  async function onSessionAction(e) {
    const btn = e.currentTarget;
    const action = btn.dataset.action;
    const pid = btn.dataset.pid;
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = '<span class="btn-dot"></span>working…';

    try {
      if (action === 'stop') {
        await api(`/sessions/${pid}/stop`, { method: 'POST' });
        toast(`Session ${pid} stopped`, 'ok');
      } else if (action === 'rebind') {
        await api(`/sessions/${pid}/stop`, { method: 'POST' });
        await api('/shell/launch', { method: 'POST' });
        toast(`Session ${pid} stopped — protected shell opened`, 'ok');
      }
      await pollSessions();
    } catch (err) {
      toast('Action failed: ' + (err.message || err), 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = original;
    }
  }

  function timeAgo(d) {
    const ms = Date.now() - d.getTime();
    if (isNaN(ms) || ms < 0) return 'just now';
    const s = Math.floor(ms / 1000);
    if (s < 60) return s + 's ago';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ago';
    const h = Math.floor(m / 60);
    if (h < 24) return h + 'h ago';
    return Math.floor(h / 24) + 'd ago';
  }

  // ---------------------------------------------------------------
  // Theme toggle (dark / light)
  // ---------------------------------------------------------------

  function initTheme() {
    const saved = localStorage.getItem('redactr.theme');
    const initial = saved || 'dark';
    applyTheme(initial);
    const btn = $('#theme-toggle');
    if (btn) btn.addEventListener('click', () => {
      const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
      applyTheme(next);
      localStorage.setItem('redactr.theme', next);
    });
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
  }

  // ---------------------------------------------------------------
  // Sessions launch button
  // ---------------------------------------------------------------

  function initSessionsActions() {
    const launch = $('#sessions-launch');
    const refresh = $('#sessions-refresh');
    if (launch) launch.addEventListener('click', async () => {
      launch.disabled = true;
      try {
        await api('/shell/launch', { method: 'POST' });
        toast('Protected shell opened in a new Terminal window', 'ok');
      } catch (err) {
        toast('Could not open shell: ' + (err.message || err), 'error');
      } finally {
        launch.disabled = false;
      }
    });
    if (refresh) refresh.addEventListener('click', pollSessions);
  }

  // ---------------------------------------------------------------
  // Detection rules state (Task 18+)
  // ---------------------------------------------------------------

  let rulesData = null;
  let pendingRuleChanges = {};         // ruleID -> bool override (used in Task 19+)
  const openGroups = new Set();
  const openTiers = new Set(['always_on', 'good_to_have']); // tier 3 collapsed by default

  async function fetchRules() {
    try {
      rulesData = await api('/rules');
      renderRules();
      updateDegradedBanner();
    } catch (err) {
      console.error('[redactr] /rules failed:', err);
    }
  }

  function updateDegradedBanner() {
    const banner = document.getElementById('hero-banner');
    const detail = document.getElementById('hero-banner-detail');
    const pill = document.getElementById('proxy-pill');
    if (!banner || !rulesData) return;

    const tier1 = rulesData.rules.filter(r => r.tier === 'always_on');
    const tier1Off = tier1.filter(r => !effectiveEnabled(r.id));

    if (tier1Off.length === 0) {
      banner.hidden = true;
      banner.classList.remove('degraded');
      if (pill) pill.dataset.degraded = 'false';
      return;
    }

    banner.hidden = false;
    const allOff = tier1Off.length === tier1.length;
    banner.classList.toggle('degraded', allOff);
    if (detail) {
      detail.textContent = `${tier1Off.length} disabled: ${tier1Off.map(r => r.label).join(', ')}.`;
    }
    if (pill) pill.dataset.degraded = 'true';
  }

  function effectiveEnabled(ruleID) {
    if (Object.prototype.hasOwnProperty.call(pendingRuleChanges, ruleID)) {
      return pendingRuleChanges[ruleID];
    }
    const r = rulesData && rulesData.rules.find(x => x.id === ruleID);
    return r ? r.enabled : false;
  }

  function groupState(group) {
    const enabledCount = group.rules.filter(id => effectiveEnabled(id)).length;
    if (enabledCount === 0) return 'off';
    if (enabledCount === group.rules.length) return 'on';
    return 'indeterminate';
  }

  function renderRules() {
    const root = document.getElementById('rule-tiers');
    if (!root || !rulesData) return;
    const search = (document.getElementById('rule-search') && document.getElementById('rule-search').value || '').toLowerCase();

    root.innerHTML = rulesData.tiers.map(tier => {
      const tierGroups = rulesData.groups.filter(g => g.tier === tier.id);
      const totalRules = tierGroups.reduce((n, g) => n + g.rules.length, 0);
      const enabledRules = tierGroups.reduce(
        (n, g) => n + g.rules.filter(id => effectiveEnabled(id)).length,
        0
      );

      const sections = tierGroups.map(group => renderGroup(group, search)).join('');
      if (search && sections.replace(/\s/g, '').length === 0) return '';

      return `
        <div class="tier-section" data-tier="${tier.id}" data-open="${openTiers.has(tier.id)}">
          <div class="tier-header" data-tier-id="${tier.id}">
            <svg class="tier-chevron" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 6 15 12 9 18"/></svg>
            <strong>${esc(tier.label)}</strong>
            <span class="tier-summary">${enabledRules} / ${totalRules} rules</span>
          </div>
          <div class="tier-body">${sections}</div>
        </div>`;
    }).join('');

    attachRuleHandlers();
  }

  function renderGroup(group, search) {
    const memberRules = group.rules.map(id => rulesData.rules.find(r => r.id === id)).filter(Boolean);
    const matches = !search ||
      group.label.toLowerCase().includes(search) ||
      memberRules.some(r =>
        r.id.includes(search) ||
        r.label.toLowerCase().includes(search) ||
        r.describe.toLowerCase().includes(search)
      );
    if (!matches) return '';

    const state = groupState(group);
    const isOpen = openGroups.has(group.id) || (search && memberRules.some(r =>
      r.id.includes(search) || r.label.toLowerCase().includes(search)
    ));
    const enabledCount = memberRules.filter(r => effectiveEnabled(r.id)).length;

    const ruleRows = memberRules.length > 1 ? memberRules.map(r => {
      if (search && !(
        r.id.includes(search) ||
        r.label.toLowerCase().includes(search) ||
        r.describe.toLowerCase().includes(search) ||
        group.label.toLowerCase().includes(search)
      )) return '';
      return `
        <div class="rule-row">
          <div class="rule-toggle" data-state="${effectiveEnabled(r.id) ? 'on' : 'off'}" data-rule="${r.id}" role="switch" aria-label="${esc(r.label)}"></div>
          <div>
            <div class="rule-id-label">${esc(r.label)}</div>
            <div class="rule-describe">${esc(r.describe)}</div>
          </div>
        </div>`;
    }).join('') : '';

    return `
      <div class="group-row" data-group="${group.id}" data-open="${isOpen}">
        <div class="group-toggle" data-state="${state}" data-group-id="${group.id}" role="switch" aria-label="${esc(group.label)}"></div>
        <div>
          <div class="group-label">${esc(group.label)}</div>
          <div class="group-meta">${enabledCount} / ${memberRules.length} rules enabled</div>
        </div>
        ${memberRules.length > 1
          ? `<button class="group-disclosure" data-disclose="${group.id}">${isOpen ? 'Hide' : 'Show'} ${memberRules.length} rules</button>`
          : ''}
      </div>
      ${memberRules.length > 1 ? `<div class="rule-list" style="display:${isOpen ? 'block' : 'none'}">${ruleRows}</div>` : ''}
    `;
  }

  function attachRuleHandlers() {
    document.querySelectorAll('.tier-header').forEach(h => {
      h.addEventListener('click', () => {
        const id = h.dataset.tierId;
        if (openTiers.has(id)) openTiers.delete(id);
        else openTiers.add(id);
        renderRules();
      });
    });

    document.querySelectorAll('[data-disclose]').forEach(b => {
      b.addEventListener('click', () => {
        const id = b.dataset.disclose;
        if (openGroups.has(id)) openGroups.delete(id);
        else openGroups.add(id);
        renderRules();
      });
    });

    document.querySelectorAll('.rule-toggle').forEach(el => {
      el.addEventListener('click', () => onRuleToggle(el.dataset.rule));
    });
    document.querySelectorAll('.group-toggle').forEach(el => {
      el.addEventListener('click', () => onGroupToggle(el.dataset.groupId));
    });
  }

  function onRuleToggle(ruleID) {
    const rule = rulesData.rules.find(r => r.id === ruleID);
    if (!rule) return;
    const current = effectiveEnabled(ruleID);
    const next = !current;
    // Enabling is always silent; disabling triggers tier-appropriate guard.
    if (current && !next) {
      confirmTierAction(rule.tier, [rule], () => commitRuleChanges({ [ruleID]: next }));
    } else {
      commitRuleChanges({ [ruleID]: next });
    }
  }

  function onGroupToggle(groupID) {
    const group = rulesData.groups.find(g => g.id === groupID);
    if (!group) return;
    const memberRules = group.rules.map(id => rulesData.rules.find(r => r.id === id)).filter(Boolean);
    const state = groupState(group);
    const turnOn = state !== 'on';
    const changes = {};
    memberRules.forEach(r => { changes[r.id] = turnOn; });
    if (turnOn) {
      commitRuleChanges(changes);
    } else {
      confirmTierAction(group.tier, memberRules, () => commitRuleChanges(changes));
    }
  }

  function commitRuleChanges(changes) {
    Object.assign(pendingRuleChanges, changes);
    renderRules();
    updateDegradedBanner();
    saveRules();
  }

  async function saveRules() {
    // Build the full rules map: existing config overrides + pending changes.
    const rulesMap = {};
    rulesData.rules.forEach(r => {
      if (Object.prototype.hasOwnProperty.call(pendingRuleChanges, r.id)) {
        rulesMap[r.id] = pendingRuleChanges[r.id];
      } else if (r.enabled !== r.default) {
        rulesMap[r.id] = r.enabled;
      }
    });
    try {
      await api('/rules', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: rulesMap }),
      });
      if (typeof toast === 'function') toast('Detection rules updated', 'ok');
      pendingRuleChanges = {};
      await fetchRules();
    } catch (err) {
      if (typeof toast === 'function') toast('Failed to save: ' + (err.message || err), 'error');
      pendingRuleChanges = {};
      await fetchRules();
    }
  }

  function confirmTierAction(tier, ruleSpecs, onConfirm) {
    if (tier === 'to_be_safer') { onConfirm(); return; }
    if (tier === 'good_to_have') { showInlinePopoverStub(ruleSpecs, onConfirm); return; }
    showTier1ModalStub(ruleSpecs, onConfirm);
  }

  // Stubs — replaced by Tasks 20 (modal) and 21 (popover).
  function showInlinePopoverStub(ruleSpecs, onConfirm) {
    // Anchor to the most-recently-rendered toggle for this rule (or its group).
    const ids = ruleSpecs.map(r => r.id);
    let anchor = document.querySelector(`[data-rule="${ids[0]}"]`);
    if (!anchor) {
      // Group-level: find the group whose rules include the first id.
      const group = rulesData.groups.find(g => g.rules.some(id => ids.includes(id)));
      if (group) anchor = document.querySelector(`[data-group-id="${group.id}"]`);
    }
    if (!anchor) {
      // Last resort — confirm via dialog so the action is never lost.
      if (window.confirm(`Disable ${ruleSpecs.length === 1 ? ruleSpecs[0].label : ruleSpecs.length + ' rules'}?`)) onConfirm();
      return;
    }

    const rect = anchor.getBoundingClientRect();
    const pop = document.createElement('div');
    pop.className = 'inline-popover';
    pop.innerHTML = `
      <div>Disable ${ruleSpecs.length === 1 ? esc(ruleSpecs[0].label) : esc(ruleSpecs.length + ' rules')}?</div>
      <div class="popover-actions">
        <button class="btn btn-ghost" data-pa="cancel">Cancel</button>
        <button class="btn btn-primary" data-pa="confirm">Disable</button>
      </div>
    `;
    document.body.appendChild(pop);

    // Position near the right edge of the anchor; clamp to viewport.
    const desiredLeft = rect.right + 8;
    const maxLeft = window.innerWidth - 260; // popover width 240 + 20 margin
    pop.style.left = `${Math.max(8, Math.min(desiredLeft, maxLeft))}px`;
    pop.style.top = `${rect.top + window.scrollY}px`;

    const cleanup = () => {
      pop.remove();
      document.removeEventListener('click', outside, true);
      document.removeEventListener('keydown', onKey);
    };
    const outside = (e) => {
      if (!pop.contains(e.target) && e.target !== anchor) cleanup();
    };
    const onKey = (e) => { if (e.key === 'Escape') cleanup(); };

    // Defer outside-click registration so the click that opened this popover
    // doesn't immediately close it.
    setTimeout(() => document.addEventListener('click', outside, true), 0);
    document.addEventListener('keydown', onKey);

    pop.querySelector('[data-pa="cancel"]').addEventListener('click', (e) => {
      e.stopPropagation();
      cleanup();
    });
    pop.querySelector('[data-pa="confirm"]').addEventListener('click', (e) => {
      e.stopPropagation();
      cleanup();
      onConfirm();
    });
  }
  function showTier1ModalStub(ruleSpecs, onConfirm) {
    const backdrop = document.getElementById('modal-backdrop');
    if (!backdrop) {
      // Fallback if modal HTML missing — preserve safe behavior.
      if (window.confirm('Disable Tier 1 protection? Affected: ' + ruleSpecs.map(r => r.label).join(', '))) onConfirm();
      return;
    }
    document.getElementById('modal-body').innerHTML = `
      <p>Disabling the following <strong>Always-On</strong> rule${ruleSpecs.length === 1 ? '' : 's'} means matching credentials or PII will be sent to the AI provider unredacted.</p>
      <ul class="modal-rule-list">
        ${ruleSpecs.map(r => `<li>${esc(r.label)}<small>${esc(r.describe)}</small></li>`).join('')}
      </ul>
      <p>Are you sure?</p>
    `;
    backdrop.hidden = false;

    const cancelBtn = document.getElementById('modal-cancel');
    const confirmBtn = document.getElementById('modal-confirm');

    const cleanup = () => {
      backdrop.hidden = true;
      cancelBtn.removeEventListener('click', onCancel);
      confirmBtn.removeEventListener('click', onConfirmClick);
      backdrop.removeEventListener('click', onBackdropClick);
      document.removeEventListener('keydown', onKey);
    };
    const onCancel = () => cleanup();
    const onConfirmClick = () => { cleanup(); onConfirm(); };
    const onBackdropClick = (e) => { if (e.target === backdrop) cleanup(); };
    const onKey = (e) => { if (e.key === 'Escape') cleanup(); };

    cancelBtn.addEventListener('click', onCancel);
    confirmBtn.addEventListener('click', onConfirmClick);
    backdrop.addEventListener('click', onBackdropClick);
    document.addEventListener('keydown', onKey);
  }

  function initRulesUI() {
    const tab = document.querySelector('[data-tab="config"]');
    if (tab) tab.addEventListener('click', fetchRules);

    const search = document.getElementById('rule-search');
    if (search) search.addEventListener('input', renderRules);

    // Also fetch immediately so the data is ready when the user opens Config.
    fetchRules();
  }

  // ---------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------

  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initTabs();
    initActions();
    initSessionsActions();
    initRulesUI();
    fetchAll();
    connectWS();
    pollSessions();
    setInterval(fetchAll, 10000);
    // Slow background poll for the runaway badge when not on the Sessions tab.
    setInterval(() => {
      if (state.activeTab !== 'sessions') pollSessions();
    }, 15000);
  });
})();
