/* KAVACH shared dashboard utilities -- reused by analyst.js, manager.js,
   and admin-console.js so all three role dashboards stay visually and
   behaviorally consistent without duplicating logic. Attaches everything
   to a single `Kavach` namespace to avoid polluting globals. */
(function () {
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const ROLE = document.body.dataset.role || '';

  const SECTOR_META = {
    hospital:   { icon: '🏥', label: 'Hospital' },
    power_grid: { icon: '⚡', label: 'Power Grid' },
    bank:       { icon: '🏦', label: 'Bank' },
  };
  const SECTOR_LABEL = { hospital: 'Hospital', power_grid: 'Power Grid', bank: 'Bank' };
  const SECTOR_COLORS = { hospital: '#3fa796', power_grid: '#c9a227', bank: '#8b3aff' };

  const ATTACK_TYPE_LABEL = {
    ddos: 'DDoS / Flood',
    bruteforce: 'Brute-Force',
    exfiltration: 'Data Exfiltration',
    ransomware: 'Ransomware',
  };
  const MITRE_MAPPING = {
    ddos: { technique_id: 'T1498', technique_name: 'Network Denial of Service' },
    bruteforce: { technique_id: 'T1110', technique_name: 'Brute Force' },
    exfiltration: { technique_id: 'T1041', technique_name: 'Exfiltration Over C2 Channel' },
    ransomware: { technique_id: 'T1486', technique_name: 'Data Encrypted for Impact' },
  };
  const STATUS_LABEL = { new: 'New', acknowledged: 'Acknowledged', resolved: 'Resolved' };

  const SECTOR_THRESHOLDS = {
    hospital: { alert_threshold: 40, critical_threshold: 75 },
    power_grid: { alert_threshold: 40, critical_threshold: 75 },
    bank: { alert_threshold: 40, critical_threshold: 75 },
  };
  function applyThresholds(thresholds) {
    if (!thresholds) return;
    Object.entries(thresholds).forEach(([sector, t]) => {
      SECTOR_THRESHOLDS[sector] = { alert_threshold: t.alert_threshold, critical_threshold: t.critical_threshold };
    });
  }
  function thresholdsFor(sector) {
    return SECTOR_THRESHOLDS[sector] || { alert_threshold: 40, critical_threshold: 75 };
  }
  function colorForScore(score, sector) {
    const t = thresholdsFor(sector);
    if (score >= t.critical_threshold) return '#c0392b';
    if (score >= t.alert_threshold) return '#d98c2b';
    return '#3fa796';
  }
  function stateForScore(score, sector) {
    const t = thresholdsFor(sector);
    if (score >= t.critical_threshold) return 'danger';
    if (score >= t.alert_threshold) return 'warn';
    return 'safe';
  }
  function levelLabel(state) {
    return state === 'danger' ? 'CRITICAL' : state === 'warn' ? 'ELEVATED' : 'NORMAL';
  }

  function animateNumber(el, from, to, duration = 500) {
    if (!el) return;
    const start = performance.now();
    function step(now) {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * eased);
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function attachMagnetic(el, strength = 14) {
    if (!el || prefersReducedMotion) return;
    el.addEventListener('mousemove', (e) => {
      const rect = el.getBoundingClientRect();
      const x = e.clientX - rect.left - rect.width / 2;
      const y = e.clientY - rect.top - rect.height / 2;
      el.style.transform = `translate(${(x / rect.width) * strength}px, ${(y / rect.height) * strength}px)`;
    });
    el.addEventListener('mouseleave', () => { el.style.transform = 'translate(0,0)'; });
  }

  function initScrollReveal() {
    const els = document.querySelectorAll('.reveal');
    if (!els.length) return;
    // Safety net: if IntersectionObserver never fires for an element
    // (blocked script elsewhere, slow layout, unsupported browser, etc.),
    // force it visible after a short delay rather than leaving critical
    // dashboard content permanently hidden at opacity:0.
    const fallback = setTimeout(() => {
      els.forEach(el => el.classList.add('is-visible'));
    }, 1200);
    try {
      const obs = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            obs.unobserve(entry.target);
          }
        });
      }, { threshold: 0.1 });
      els.forEach(el => obs.observe(el));
    } catch (e) {
      els.forEach(el => el.classList.add('is-visible'));
    }
    return fallback;
  }

  // ---------- siege / propagation map (shared markup: #siege-map svg with
  // node-<sector> groups and edge-<from>-<to> lines, same as the original
  // dashboard) ----------
  function resetSiegeMap() {
    document.querySelectorAll('.edge').forEach(e => e.classList.remove('active'));
    document.querySelectorAll('.node-group').forEach(n => n.classList.remove('danger'));
  }
  function updatePropagation(propagation, sectors) {
    if (!document.getElementById('siege-map')) return;
    resetSiegeMap();
    Object.keys(sectors).forEach(key => {
      if (stateForScore(sectors[key].risk_score, key) === 'danger') {
        const node = document.getElementById(`node-${key}`);
        if (node) node.classList.add('danger');
      }
    });
    (propagation || []).forEach(({ from, to }) => {
      const edge = document.getElementById(`edge-${from}-${to}`);
      if (edge) edge.classList.add('active');
    });
  }
  const SIEGE_EDGES = [
    { id: 'power_grid-hospital', x1: 150, y1: 130, x2: 450, y2: 70 },
    { id: 'bank-hospital', x1: 150, y1: 220, x2: 450, y2: 70 },
  ];
  function buildEdgePulses() {
    const svg = document.getElementById('siege-map');
    if (!svg) return;
    SIEGE_EDGES.forEach(edge => {
      const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('r', '5');
      c.setAttribute('class', 'edge-pulse');
      c.id = `pulse-${edge.id}`;
      svg.appendChild(c);
    });
  }
  let pulseClock = null;
  function animatePulses(timestamp) {
    if (pulseClock === null) pulseClock = timestamp;
    SIEGE_EDGES.forEach(edge => {
      const line = document.getElementById(`edge-${edge.id}`);
      const pulse = document.getElementById(`pulse-${edge.id}`);
      if (!line || !pulse) { return; }
      if (line.classList.contains('active')) {
        pulse.classList.add('is-active');
        const t = ((timestamp - pulseClock) % 1400) / 1400;
        pulse.setAttribute('cx', (edge.x1 + (edge.x2 - edge.x1) * t).toFixed(1));
        pulse.setAttribute('cy', (edge.y1 + (edge.y2 - edge.y1) * t).toFixed(1));
      } else {
        pulse.classList.remove('is-active');
      }
    });
    requestAnimationFrame(animatePulses);
  }

  // ---------- risk history chart (Chart.js line, one dataset per sector) ----------
  function initHistoryChart(canvasId, legendId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || typeof Chart === 'undefined') return null;

    const datasets = Object.keys(SECTOR_META).map(key => ({
      label: SECTOR_META[key].label,
      data: [],
      borderColor: SECTOR_COLORS[key],
      backgroundColor: 'transparent',
      borderWidth: 2,
      pointRadius: 0,
      tension: 0.3,
      _sector: key,
    }));

    const chart = new Chart(canvas.getContext('2d'), {
      type: 'line',
      data: { labels: [], datasets },
      options: {
        responsive: true,
        animation: false,
        interaction: { mode: 'nearest', intersect: false },
        scales: {
          x: { display: false },
          y: {
            min: 0, max: 100,
            grid: { color: 'rgba(255,255,255,0.05)' },
            ticks: { color: '#9aa0b4', font: { family: 'JetBrains Mono', size: 10 } },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#131826', titleColor: '#e8e6de', bodyColor: '#e8e6de',
            borderColor: 'rgba(201,162,39,0.3)', borderWidth: 1,
          },
        },
      },
    });

    const legend = document.getElementById(legendId);
    if (legend) {
      legend.innerHTML = Object.entries(SECTOR_META).map(([key, meta]) =>
        `<span class="legend-item"><span class="legend-dot" style="background:${SECTOR_COLORS[key]}"></span>${meta.label}</span>`
      ).join('');
    }

    Object.keys(SECTOR_META).forEach(key => {
      fetch(`/api/history/${key}`)
        .then(r => r.json())
        .then(points => {
          if (!Array.isArray(points)) return;
          const ds = chart.data.datasets.find(d => d._sector === key);
          if (!ds) return;
          ds.data = points.map(p => p.risk_score);
          if (chart.data.labels.length < points.length) {
            chart.data.labels = points.map((_, i) => i);
          }
          chart.update('none');
        })
        .catch(() => {});
    });

    return chart;
  }
  function pushHistoryPoint(chart, sectors) {
    if (!chart) return;
    chart.data.labels.push(chart.data.labels.length);
    if (chart.data.labels.length > 120) chart.data.labels.shift();
    chart.data.datasets.forEach(ds => {
      const val = sectors[ds._sector] ? sectors[ds._sector].risk_score : null;
      ds.data.push(val);
      if (ds.data.length > 120) ds.data.shift();
    });
    chart.update('none');
  }

  // ---------- audio alert (used only where a dashboard wants it) ----------
  let audioCtx = null;
  function ensureAudioCtx() {
    if (!audioCtx) {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      audioCtx = new Ctx();
    }
    if (audioCtx.state === 'suspended') audioCtx.resume();
    return audioCtx;
  }
  function playAlertTone() {
    try {
      const ctx = ensureAudioCtx();
      const now = ctx.currentTime;
      [0, 0.22].forEach((offset, i) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.value = i === 0 ? 880 : 660;
        gain.gain.setValueAtTime(0, now + offset);
        gain.gain.linearRampToValueAtTime(0.18, now + offset + 0.02);
        gain.gain.linearRampToValueAtTime(0, now + offset + 0.18);
        osc.connect(gain).connect(ctx.destination);
        osc.start(now + offset);
        osc.stop(now + offset + 0.2);
      });
    } catch (e) { /* audio not available */ }
  }

  function fmtTime(ts) {
    return new Date(ts * 1000).toLocaleTimeString();
  }

  function csvDownload(filename, rows, header) {
    const csvLines = [header.join(',')];
    rows.forEach(r => csvLines.push(r.join(',')));
    const blob = new Blob([csvLines.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  window.Kavach = {
    ROLE, prefersReducedMotion,
    SECTOR_META, SECTOR_LABEL, SECTOR_COLORS, ATTACK_TYPE_LABEL, MITRE_MAPPING, STATUS_LABEL,
    applyThresholds, thresholdsFor, colorForScore, stateForScore, levelLabel,
    animateNumber, attachMagnetic, initScrollReveal,
    resetSiegeMap, updatePropagation, buildEdgePulses, animatePulses,
    initHistoryChart, pushHistoryPoint,
    playAlertTone, fmtTime, csvDownload,
  };
})();