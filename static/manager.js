(function () {
  const K = window.Kavach;

  // Reveal all panels immediately/robustly -- must run before anything else
  // in this file that could throw (see analyst.js for why).
  K.initScrollReveal();

  const globalStatus = document.getElementById('global-status');
  const globalStatusText = document.getElementById('global-status-text');

  const orgRiskEl = document.getElementById('posture-org-risk');
  const statusLabelEl = document.getElementById('posture-status-label');
  const criticalEl = document.getElementById('posture-critical');
  const activeEl = document.getElementById('posture-active');
  const incidents24hEl = document.getElementById('posture-incidents-24h');

  const riskCompareList = document.getElementById('risk-compare-list');
  const impactGrid = document.getElementById('impact-grid');
  const recommendList = document.getElementById('recommend-list');
  const incidentSummaryList = document.getElementById('incident-summary-list');
  const incidentSummaryEmpty = document.getElementById('incident-summary-empty');

  let METRIC_BASELINES = null;
  let latestSectors = {};
  let allSummaryLogs = [];

  fetch('/api/metrics/baselines').then(r => r.json()).then(b => { METRIC_BASELINES = b; }).catch(() => {});

  function refreshPostureKpis() {
    fetch('/api/incident-kpis').then(r => r.json()).then(k => {
      if (criticalEl) K.animateNumber(criticalEl, parseInt(criticalEl.textContent, 10) || 0, k.critical);
      if (activeEl) K.animateNumber(activeEl, parseInt(activeEl.textContent, 10) || 0, k.active_incidents);
      if (incidents24hEl) K.animateNumber(incidents24hEl, parseInt(incidents24hEl.textContent, 10) || 0, k.incidents_24h);
    }).catch(() => {});
  }

  // ---------- security posture (org risk rollup, reused from telemetry payload) ----------
  function updatePosture(summary) {
    if (!summary || !orgRiskEl) return;
    K.animateNumber(orgRiskEl, parseFloat(orgRiskEl.textContent) || 0, summary.org_risk);
    statusLabelEl.textContent = summary.status_label;
    statusLabelEl.className = 'exec-metric-status ' + (
      summary.org_risk >= 75 ? 'exec-status-danger' : summary.org_risk >= 45 ? 'exec-status-warn' : 'exec-status-safe'
    );
  }

  // ---------- risk by sector comparison ----------
  function renderRiskCompare(sectors) {
    if (!riskCompareList) return;
    const rows = Object.entries(sectors).sort((a, b) => b[1].risk_score - a[1].risk_score);
    riskCompareList.innerHTML = rows.map(([key, data]) => {
      const score = Math.round(data.risk_score);
      const state = K.stateForScore(score, key);
      const color = K.colorForScore(score, key);
      return `
        <div class="risk-compare-row">
          <div class="risk-compare-top">
            <span class="risk-compare-name">${K.SECTOR_LABEL[key] || key}</span>
            <span class="risk-compare-score" style="color:${color}">${score}</span>
          </div>
          <div class="risk-compare-track"><div class="risk-compare-fill" style="width:${score}%; background:${color};"></div></div>
          <span class="risk-compare-level" style="color:${color}">${K.levelLabel(state)}</span>
        </div>`;
    }).join('');
  }

  // ---------- business impact (derived from live metrics vs known baselines) ----------
  const IMPACT_METRIC_MAP = [
    { key: 'network_traffic_mbps', label: 'Network availability' },
    { key: 'active_connections', label: 'Service disruption' },
    { key: 'data_egress_mb', label: 'Data confidentiality' },
    { key: 'cpu_usage_pct', label: 'Infrastructure impact' },
  ];
  function impactLevel(deviationRatio) {
    if (deviationRatio >= 3) return { label: 'Severe', cls: 'level-severe' };
    if (deviationRatio >= 1.5) return { label: 'Elevated', cls: 'level-elevated' };
    return { label: 'Normal', cls: 'level-normal' };
  }
  function renderBusinessImpact(sectors) {
    if (!impactGrid || !METRIC_BASELINES) return;
    impactGrid.innerHTML = Object.entries(sectors).map(([key, data]) => {
      const metrics = data.metrics || {};
      const rows = IMPACT_METRIC_MAP.map(({ key: mkey, label }) => {
        const baseline = METRIC_BASELINES[mkey];
        if (!baseline || metrics[mkey] == null) return '';
        const [mean, std] = baseline;
        const deviation = std > 0 ? Math.abs(metrics[mkey] - mean) / std : 0;
        const ratio = 1 + deviation / 3;
        const lvl = impactLevel(ratio);
        return `<div class="impact-metric"><span class="impact-metric-name">${label}</span><span class="impact-metric-val ${lvl.cls}">${lvl.label}</span></div>`;
      }).join('');
      return `<div class="impact-card"><div class="impact-sector">${K.SECTOR_LABEL[key] || key}</div>${rows}</div>`;
    }).join('');
  }

  // ---------- recommended action ----------
  function renderRecommendations(sectors, propagation, summary) {
    if (!recommendList) return;
    const cards = [];
    const sorted = Object.entries(sectors).sort((a, b) => b[1].risk_score - a[1].risk_score);
    const [topKey, topData] = sorted[0] || [];
    if (topData && K.stateForScore(topData.risk_score, topKey) === 'danger') {
      const sourceEdges = (propagation || []).filter(p => p.to === topKey);
      let text;
      if (sourceEdges.length) {
        const sources = sourceEdges.map(e => K.SECTOR_LABEL[e.from] || e.from).join(', ');
        text = `<b>${K.SECTOR_LABEL[topKey]}</b> risk increased significantly due to propagated attack from <b>${sources}</b>. Recommended response: isolate the affected ${K.SECTOR_LABEL[topKey].toLowerCase()} network and escalate to SOC Analyst.`;
      } else {
        text = `<b>${K.SECTOR_LABEL[topKey]}</b> is at critical risk (${Math.round(topData.risk_score)}/100). Recommended response: escalate to SOC Analyst for immediate investigation and containment.`;
      }
      cards.push(`<div class="recommend-card priority-high"><span class="recommend-icon">⚠</span><span class="recommend-body">${text}</span></div>`);
    } else if (topData && K.stateForScore(topData.risk_score, topKey) === 'warn') {
      cards.push(`<div class="recommend-card"><span class="recommend-icon">👁</span><span class="recommend-body"><b>${K.SECTOR_LABEL[topKey]}</b> risk is elevated (${Math.round(topData.risk_score)}/100). Recommended action: continue monitoring; no escalation required yet.</span></div>`);
    } else {
      cards.push(`<div class="recommend-card"><span class="recommend-icon">✅</span><span class="recommend-body">All sectors within normal risk bounds. No action required at this time.</span></div>`);
    }
    if (summary && summary.incidents_24h > 0) {
      cards.push(`<div class="recommend-card"><span class="recommend-icon">📄</span><span class="recommend-body">${summary.incidents_24h} confirmed incident${summary.incidents_24h === 1 ? '' : 's'} in the last 24 hours. Consider reviewing the incident report for the highest-risk sector.</span></div>`);
    }
    recommendList.innerHTML = cards.join('');
  }

  // ---------- incident summary (read-only, no triage actions for Manager) ----------
  function renderIncidentSummary() {
    if (!incidentSummaryList) return;
    const rows = allSummaryLogs.filter(e => e.status).slice(-20).reverse();
    incidentSummaryList.innerHTML = '';
    if (rows.length === 0) {
      incidentSummaryEmpty.style.display = 'block';
      return;
    }
    incidentSummaryEmpty.style.display = 'none';
    rows.forEach(entry => {
      const row = document.createElement('div');
      row.className = `alert-row sev-${entry.severity}`;
      const statusBadge = `<span class="status-badge status-${entry.status}">${K.STATUS_LABEL[entry.status] || entry.status}</span>`;
      row.innerHTML = `
        <div class="alert-row-main">
          <div class="alert-row-top">
            <span class="sector-tag">${K.SECTOR_LABEL[entry.sector] || entry.sector}</span>
            ${statusBadge}<span class="alert-row-meta">${entry.time}</span>
          </div>
          <div class="alert-row-msg">${entry.message}</div>
        </div>
        <div class="alert-risk" style="color:${entry.severity === 'high' ? '#e57368' : '#d98c2b'}">${entry.severity === 'high' ? 'HIGH' : 'MED'}</div>
      `;
      incidentSummaryList.appendChild(row);
    });
  }

  // ---------- init ----------
  K.buildEdgePulses();
  requestAnimationFrame(K.animatePulses);
  const historyChart = K.initHistoryChart('history-chart', 'history-legend');
  refreshPostureKpis();
  setInterval(refreshPostureKpis, 8000);

  const reportSectorEl = document.getElementById('report-sector');
  const reportBtn = document.getElementById('report-btn');
  const reportBtnPdf = document.getElementById('report-btn-pdf');
  function updateReportLink() {
    if (!reportSectorEl) return;
    if (reportBtn) reportBtn.href = `/report/${reportSectorEl.value}`;
    if (reportBtnPdf) reportBtnPdf.href = `/report/${reportSectorEl.value}/pdf`;
  }
  if (reportSectorEl) { reportSectorEl.addEventListener('change', updateReportLink); updateReportLink(); }

  const socket = io();
  socket.on('telemetry_update', (payload) => {
    if (payload.thresholds) K.applyThresholds(payload.thresholds);
    latestSectors = payload.sectors;
    renderRiskCompare(payload.sectors);
    renderBusinessImpact(payload.sectors);
    renderRecommendations(payload.sectors, payload.propagation, payload.exec_summary);
    K.updatePropagation(payload.propagation, payload.sectors);
    K.pushHistoryPoint(historyChart, payload.sectors);
    if (payload.exec_summary) updatePosture(payload.exec_summary);
    if (payload.new_log) {
      allSummaryLogs.push(...payload.new_log);
      renderIncidentSummary();
      refreshPostureKpis();
    }
  });
  socket.on('log_history', (payload) => { allSummaryLogs.push(...(payload.log || [])); renderIncidentSummary(); });
  socket.on('thresholds_bulk', (payload) => K.applyThresholds(payload.thresholds));
  socket.on('thresholds_updated', (payload) => K.applyThresholds({ [payload.sector]: payload }));
  socket.on('demo_reset', () => { allSummaryLogs.length = 0; renderIncidentSummary(); refreshPostureKpis(); });
  socket.on('connect', () => { if (globalStatusText) globalStatusText.textContent = 'MONITORING'; });
  socket.on('disconnect', () => {
    if (globalStatus) globalStatus.classList.add('alert');
    if (globalStatusText) globalStatusText.textContent = 'DISCONNECTED';
  });
})();