(function () {
  const K = window.Kavach;

  // Reveal all panels immediately/robustly -- this must run before anything
  // else in this file that could throw, so a later error never leaves the
  // dashboard's content permanently hidden at opacity:0.
  K.initScrollReveal();

  const GAUGE_RADIUS = 38;
  const GAUGE_CIRC = 2 * Math.PI * GAUGE_RADIUS;
  const SPARK_W = 140, SPARK_H = 34;
  const HISTORY_LEN = 30;
  const sparkHistory = {};

  const grid = document.getElementById('sector-grid');
  const alertQueue = document.getElementById('alert-queue');
  const alertEmpty = document.getElementById('alert-empty');
  const filterSectorEl = document.getElementById('filter-sector');
  const filterSeverityEl = document.getElementById('filter-severity');
  const filterStatusEl = document.getElementById('filter-status');
  const exportBtn = document.getElementById('export-csv');
  const muteBtn = document.getElementById('mute-btn');
  const globalStatus = document.getElementById('global-status');
  const globalStatusText = document.getElementById('global-status-text');
  const auditScroll = document.getElementById('audit-scroll');
  const auditEmpty = document.getElementById('audit-empty');

  let allLogs = [];
  let allAudit = [];
  let wasAlertActive = false;
  let muted = false;

  // ---------- sector risk cards (with SOC response actions) ----------
  function buildCards() {
    if (!grid) return;
    Object.entries(K.SECTOR_META).forEach(([key, meta]) => {
      const card = document.createElement('div');
      card.className = 'sector-card state-safe';
      card.id = `card-${key}`;
      card.innerHTML = `
        <div class="card-head">
          <div style="display:flex; align-items:center; gap:10px;">
            <span class="icon">${meta.icon}</span>
            <span class="sector-name">${meta.label}</span>
            <span class="source-badge" id="source-${key}" style="display:none;"></span>
          </div>
          <span class="badge safe" id="badge-${key}">Secure</span>
        </div>
        <div class="gauge-wrap">
          <div class="gauge">
            <svg viewBox="0 0 92 92">
              <circle class="gauge-track" cx="46" cy="46" r="${GAUGE_RADIUS}"></circle>
              <circle class="gauge-fill" id="gauge-${key}" cx="46" cy="46" r="${GAUGE_RADIUS}"
                stroke="#3fa796" stroke-dasharray="0 ${GAUGE_CIRC}"></circle>
            </svg>
          </div>
          <div>
            <div class="risk-number" id="risk-${key}">0</div>
            <div class="risk-label">Risk Score</div>
          </div>
        </div>
        <div class="spark-wrap">
          <span class="spark-label">Risk trend</span>
          <svg class="sparkline" id="spark-${key}" viewBox="0 0 ${SPARK_W} ${SPARK_H}" preserveAspectRatio="none">
            <polyline id="spark-line-${key}" points=""></polyline>
          </svg>
        </div>
        <div class="top-factor" id="factor-${key}">Awaiting telemetry…</div>
        <div class="attack-type-row" id="attack-type-${key}"></div>
        <div class="blast-radius" id="blast-${key}"></div>
        <div class="card-actions">
          <button class="simulate-btn" id="simulate-${key}" data-sector="${key}">⚔ Simulate Attack</button>
          <div class="card-actions-row">
            <button class="contain-btn" id="contain-${key}" data-sector="${key}">🛡 Contain</button>
            <button class="fp-btn" id="fp-${key}" data-sector="${key}">✕ False Positive</button>
          </div>
        </div>
      `;
      sparkHistory[key] = [];
      grid.appendChild(card);

      card.querySelector(`#simulate-${key}`).addEventListener('click', (e) => {
        socket.emit('trigger_attack', { sector: key });
        const btn = e.currentTarget;
        btn.textContent = '⚔ Triggered…'; btn.disabled = true;
        setTimeout(() => { btn.textContent = '⚔ Simulate Attack'; btn.disabled = false; }, 4000);
      });
      card.querySelector(`#contain-${key}`).addEventListener('click', (e) => {
        if (!confirm(`Engage containment on ${meta.label}? This actively suppresses reported risk while isolation holds.`)) return;
        socket.emit('contain_sector', { sector: key });
        const btn = e.currentTarget;
        btn.textContent = '🛡 Containing…'; btn.disabled = true;
        setTimeout(() => { btn.textContent = '🛡 Contain'; btn.disabled = false; }, 12000);
      });
      card.querySelector(`#fp-${key}`).addEventListener('click', (e) => {
        socket.emit('mark_false_positive', { sector: key });
        const btn = e.currentTarget;
        btn.textContent = '✕ Noted'; btn.disabled = true;
        setTimeout(() => { btn.textContent = '✕ False Positive'; btn.disabled = false; }, 4000);
      });
    });
  }

  function updateSparkline(key, score) {
    const arr = sparkHistory[key];
    arr.push(score);
    if (arr.length > HISTORY_LEN) arr.shift();
    const line = document.getElementById(`spark-line-${key}`);
    if (!line) return;
    const n = arr.length;
    const points = arr.map((v, i) => {
      const x = n === 1 ? SPARK_W : (i / (HISTORY_LEN - 1)) * SPARK_W;
      const y = SPARK_H - (v / 100) * SPARK_H;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    line.setAttribute('points', points);
    line.setAttribute('stroke', K.colorForScore(arr[arr.length - 1], key));
  }

  function updateCard(key, data) {
    const score = Math.round(data.risk_score);
    const state = K.stateForScore(score, key);
    const color = K.colorForScore(score, key);
    const card = document.getElementById(`card-${key}`);
    if (!card) return;
    card.classList.remove('state-safe', 'state-warn', 'state-danger');
    card.classList.add(`state-${state}`);

    const riskEl = document.getElementById(`risk-${key}`);
    const prevScore = parseInt(riskEl.textContent, 10);
    if (!Number.isNaN(prevScore) && prevScore !== score) {
      K.animateNumber(riskEl, prevScore, score);
    } else {
      riskEl.textContent = score;
    }
    riskEl.style.color = color;

    const gauge = document.getElementById(`gauge-${key}`);
    const filled = (score / 100) * GAUGE_CIRC;
    gauge.setAttribute('stroke-dasharray', `${filled} ${GAUGE_CIRC}`);
    gauge.setAttribute('stroke', color);

    const badge = document.getElementById(`badge-${key}`);
    badge.className = `badge ${state === 'danger' ? 'danger' : state === 'warn' ? 'warn' : 'safe'}`;
    badge.textContent = state === 'danger' ? 'Anomaly' : state === 'warn' ? 'Elevated' : 'Secure';

    const sourceBadge = document.getElementById(`source-${key}`);
    if (sourceBadge) {
      if (data.data_source === 'replay') {
        sourceBadge.textContent = '⏺ REPLAY';
        sourceBadge.style.display = 'inline-block';
      } else {
        sourceBadge.style.display = 'none';
      }
    }

    updateSparkline(key, score);

    const factorEl = document.getElementById(`factor-${key}`);
    const factorName = (data.top_factor || '').replace(/_/g, ' ');
    factorEl.innerHTML = `Top factor: <b>${factorName}</b> · ${data.metrics ? data.metrics[data.top_factor] : ''}`;

    const attackRow = document.getElementById(`attack-type-${key}`);
    if (data.contained) {
      attackRow.innerHTML = `<span class="attack-chip contained">🛡 Contained — risk suppressed</span>`;
    } else if (data.predicted_attack_type) {
      const label = K.ATTACK_TYPE_LABEL[data.predicted_attack_type] || data.predicted_attack_type;
      const pct = Math.round((data.attack_confidence || 0) * 100);
      const mitre = K.MITRE_MAPPING[data.predicted_attack_type];
      const mitreTag = mitre ? `<span class="mitre-tag" title="${mitre.technique_name}">${mitre.technique_id}</span>` : '';
      attackRow.innerHTML = `<span class="attack-chip">⚠ ${label} <em>${pct}% match</em></span>${mitreTag}`;
    } else {
      attackRow.innerHTML = '';
    }

    const blastEl = document.getElementById(`blast-${key}`);
    if (data.blast_radius) {
      const b = data.blast_radius;
      const pct = Math.round(b.probability * 100);
      blastEl.innerHTML = `<span class="blast-chip">⏱ Trending to critical in ~${Math.round(b.eta_seconds)}s <em>(${pct}% likely)</em></span>`;
      blastEl.style.display = 'block';
    } else {
      blastEl.innerHTML = '';
      blastEl.style.display = 'none';
    }
  }

  // ---------- KPI row ----------
  function refreshKpis() {
    fetch('/api/incident-kpis').then(r => r.json()).then(k => {
      const critEl = document.getElementById('kpi-critical');
      const newEl = document.getElementById('kpi-new');
      const activeEl = document.getElementById('kpi-active');
      const containedEl = document.getElementById('kpi-contained');
      if (critEl) K.animateNumber(critEl, parseInt(critEl.textContent, 10) || 0, k.critical);
      if (newEl) K.animateNumber(newEl, parseInt(newEl.textContent, 10) || 0, k.new);
      if (activeEl) K.animateNumber(activeEl, parseInt(activeEl.textContent, 10) || 0, k.active_incidents);
      if (containedEl) K.animateNumber(containedEl, parseInt(containedEl.textContent, 10) || 0, k.contained_sectors);
    }).catch(() => {});
  }

  // ---------- alert queue ----------
  const STATUS_NEXT = { new: 'acknowledged', acknowledged: 'resolved' };
  const STATUS_NEXT_LABEL = { new: 'Acknowledge', acknowledged: 'Resolve' };

  function getFilteredLogs() {
    const sectorFilter = filterSectorEl ? filterSectorEl.value : 'all';
    const severityFilter = filterSeverityEl ? filterSeverityEl.value : 'all';
    const statusFilter = filterStatusEl ? filterStatusEl.value : 'all';
    return allLogs.filter(e =>
      (sectorFilter === 'all' || e.sector === sectorFilter) &&
      (severityFilter === 'all' || e.severity === severityFilter) &&
      (statusFilter === 'all' || e.status === statusFilter)
    );
  }

  function renderAlertQueue() {
    if (!alertQueue) return;
    const filtered = getFilteredLogs().filter(e => e.status).slice(-60).reverse();
    alertQueue.innerHTML = '';
    if (filtered.length === 0) {
      alertEmpty.style.display = 'block';
      return;
    }
    alertEmpty.style.display = 'none';

    filtered.forEach(entry => {
      const row = document.createElement('div');
      row.className = `alert-row sev-${entry.severity}`;
      row.dataset.logId = entry.id;
      const mitre = entry.mitre_id ? `<span class="mitre-tag" title="${entry.mitre_label || ''}">${entry.mitre_id}</span>` : '';
      const statusBadge = `<span class="status-badge status-${entry.status}">${K.STATUS_LABEL[entry.status] || entry.status}</span>`;
      const nextStatus = STATUS_NEXT[entry.status];
      const actions = [];
      actions.push(`<button class="mini-btn investigate-btn" data-sector="${entry.sector}">🔍 Investigate</button>`);
      if (nextStatus) actions.push(`<button class="mini-btn triage-btn" data-id="${entry.id}" data-status="${nextStatus}">${STATUS_NEXT_LABEL[entry.status]}</button>`);
      if (entry.status !== 'new') actions.push(`<button class="mini-btn triage-btn" data-id="${entry.id}" data-status="new">Reopen</button>`);
      actions.push(`<button class="mini-btn danger contain-inline-btn" data-sector="${entry.sector}">🛡 Contain</button>`);

      row.innerHTML = `
        <div class="alert-row-main">
          <div class="alert-row-top">
            <span class="sector-tag">${K.SECTOR_LABEL[entry.sector] || entry.sector}</span>
            ${mitre}${statusBadge}
            <span class="alert-row-meta">${entry.time}</span>
          </div>
          <div class="alert-row-msg">${entry.message}</div>
        </div>
        <div class="alert-risk" style="color:${entry.severity === 'high' ? '#e57368' : '#d98c2b'}">${entry.severity === 'high' ? 'HIGH' : 'MED'}</div>
        <div class="alert-actions">${actions.join('')}</div>
      `;
      alertQueue.appendChild(row);
    });

    alertQueue.querySelectorAll('.triage-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        socket.emit('update_alert_status', { id: parseInt(btn.dataset.id, 10), status: btn.dataset.status });
        btn.disabled = true;
      });
    });
    alertQueue.querySelectorAll('.investigate-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const card = document.getElementById(`card-${btn.dataset.sector}`);
        if (card) { card.scrollIntoView({ behavior: 'smooth', block: 'center' }); card.classList.add('is-hovering'); setTimeout(() => card.classList.remove('is-hovering'), 1200); }
      });
    });
    alertQueue.querySelectorAll('.contain-inline-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!confirm('Engage containment on this sector?')) return;
        socket.emit('contain_sector', { sector: btn.dataset.sector });
        btn.disabled = true;
      });
    });
  }

  function addLogEntries(entries) {
    if (!entries || entries.length === 0) return;
    allLogs.push(...entries);
    renderAlertQueue();
    refreshKpis();
  }
  function applyAlertStatusUpdate({ id, status }) {
    const entry = allLogs.find(e => e.id === id);
    if (!entry) return;
    entry.status = status;
    renderAlertQueue();
    refreshKpis();
  }

  function downloadCSV() {
    const rows = getFilteredLogs().map(r => [
      r.time, r.sector, r.severity, `"${(r.message || '').replace(/"/g, '""')}"`, r.status || '', r.mitre_id || '',
    ]);
    K.csvDownload(`kavach_alert_queue_${Date.now()}.csv`, rows, ['time', 'sector', 'severity', 'message', 'status', 'mitre_id']);
  }

  // ---------- audit trail ----------
  const AUDIT_ACTION_ICON = {
    'Triggered attack simulation': '⚔', 'Contained sector': '🛡', 'Marked false positive': '✕',
    'Acknowledged alert': '👁', 'Resolved alert': '✅', 'Reopened alert': '↩',
  };
  function renderAudit() {
    if (!auditScroll) return;
    if (allAudit.length === 0) {
      auditEmpty.style.display = 'block';
      auditScroll.innerHTML = '';
      auditScroll.appendChild(auditEmpty);
      return;
    }
    auditEmpty.style.display = 'none';
    auditScroll.innerHTML = '';
    allAudit.slice(-60).reverse().forEach(entry => {
      const icon = AUDIT_ACTION_ICON[entry.action] || '•';
      const sectorTag = entry.sector ? `<span class="sector-tag">${K.SECTOR_LABEL[entry.sector] || entry.sector}</span>` : '';
      const detail = entry.detail ? ` — ${entry.detail}` : '';
      const div = document.createElement('div');
      div.className = 'audit-entry';
      div.innerHTML = `
        <span class="time">${entry.time}</span>
        <span class="audit-actor">${icon} ${entry.actor} <span class="audit-role">(${entry.role})</span></span>
        ${sectorTag}<span class="msg">${entry.action}${detail}</span>`;
      auditScroll.appendChild(div);
    });
  }
  function addAuditEntries(entries) {
    if (!entries || entries.length === 0) return;
    allAudit.push(...entries);
    renderAudit();
  }

  // ---------- connection status ----------
  function updateGlobalStatus(sectors) {
    const anyDanger = Object.entries(sectors).some(([key, s]) => K.stateForScore(s.risk_score, key) === 'danger');
    if (anyDanger) {
      globalStatus.classList.add('alert');
      globalStatusText.textContent = 'THREAT ACTIVE';
      if (!wasAlertActive && !muted) K.playAlertTone();
      wasAlertActive = true;
    } else {
      globalStatus.classList.remove('alert');
      globalStatusText.textContent = 'MONITORING';
      wasAlertActive = false;
    }
  }

  // ---------- init ----------
  buildCards();
  K.buildEdgePulses();
  K.attachMagnetic(muteBtn, 8);
  K.attachMagnetic(exportBtn, 8);
  requestAnimationFrame(K.animatePulses);
  const historyChart = K.initHistoryChart('history-chart', 'history-legend');
  refreshKpis();
  setInterval(refreshKpis, 6000);

  if (muteBtn) {
    muteBtn.addEventListener('click', () => {
      muted = !muted;
      muteBtn.classList.toggle('is-muted', muted);
      muteBtn.textContent = muted ? '🔇' : '🔊';
    });
  }
  if (filterSectorEl) filterSectorEl.addEventListener('change', renderAlertQueue);
  if (filterSeverityEl) filterSeverityEl.addEventListener('change', renderAlertQueue);
  if (filterStatusEl) filterStatusEl.addEventListener('change', renderAlertQueue);
  if (exportBtn) exportBtn.addEventListener('click', downloadCSV);

  const reportSectorEl = document.getElementById('report-sector');
  const reportBtn = document.getElementById('report-btn');
  const reportBtnPdf = document.getElementById('report-btn-pdf');
  function updateReportLink() {
    if (!reportSectorEl) return;
    if (reportBtn) reportBtn.href = `/report/${reportSectorEl.value}`;
    if (reportBtnPdf) reportBtnPdf.href = `/report/${reportSectorEl.value}/pdf`;
  }
  if (reportSectorEl) { reportSectorEl.addEventListener('change', updateReportLink); updateReportLink(); }

  // ---------- socket wiring ----------
  const socket = io();
  socket.on('telemetry_update', (payload) => {
    if (payload.thresholds) K.applyThresholds(payload.thresholds);
    Object.entries(payload.sectors).forEach(([key, data]) => updateCard(key, data));
    K.updatePropagation(payload.propagation, payload.sectors);
    updateGlobalStatus(payload.sectors);
    K.pushHistoryPoint(historyChart, payload.sectors);
    if (payload.new_log) addLogEntries(payload.new_log);
  });
  socket.on('log_history', (payload) => addLogEntries(payload.log));
  socket.on('audit_log', (payload) => addAuditEntries(payload.entries));
  socket.on('thresholds_bulk', (payload) => K.applyThresholds(payload.thresholds));
  socket.on('thresholds_updated', (payload) => K.applyThresholds({ [payload.sector]: payload }));
  socket.on('alert_status_updated', (payload) => applyAlertStatusUpdate(payload));
  socket.on('demo_reset', () => {
    allLogs.length = 0; allAudit.length = 0;
    renderAlertQueue(); renderAudit(); refreshKpis();
  });
  socket.on('connect', () => { if (globalStatusText) globalStatusText.textContent = 'MONITORING'; });
  socket.on('disconnect', () => {
    if (globalStatus) globalStatus.classList.add('alert');
    if (globalStatusText) globalStatusText.textContent = 'DISCONNECTED';
  });
})();