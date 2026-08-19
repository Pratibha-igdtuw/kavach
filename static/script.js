const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const ROLE = document.body.dataset.role || 'executive';
// Analyst: full operational control. Admin: same operational control PLUS
// user/threshold management via the /admin panel. Executive: read-only.
const IS_ANALYST = ROLE === 'analyst' || ROLE === 'admin';
const SHOW_EXEC_SUMMARY = ROLE === 'executive' || ROLE === 'admin';
const IS_EXEC = ROLE === 'executive';
const IS_ADMIN = ROLE === 'admin';

const SECTOR_META = {
  hospital:   { icon: '🏥', label: 'Hospital' },
  power_grid: { icon: '⚡', label: 'Power Grid' },
  bank:       { icon: '🏦', label: 'Bank' },
};

const ATTACK_TYPE_LABEL = {
  ddos: 'DDoS / Flood',
  bruteforce: 'Brute-Force',
  exfiltration: 'Data Exfiltration',
  ransomware: 'Ransomware',
};

// Mirrors simulator.MITRE_MAPPING on the backend — used to annotate attack
// chips and log entries with the MITRE ATT&CK technique they map to.
const MITRE_MAPPING = {
  ddos: { technique_id: 'T1498', technique_name: 'Network Denial of Service' },
  bruteforce: { technique_id: 'T1110', technique_name: 'Brute Force' },
  exfiltration: { technique_id: 'T1041', technique_name: 'Exfiltration Over C2 Channel' },
  ransomware: { technique_id: 'T1486', technique_name: 'Data Encrypted for Impact' },
};

// Alert triage queue: New -> Acknowledged -> Resolved.
const STATUS_LABEL = { new: 'New', acknowledged: 'Acknowledged', resolved: 'Resolved' };
const STATUS_NEXT = { new: 'acknowledged', acknowledged: 'resolved' };
const STATUS_NEXT_LABEL = { new: 'Acknowledge', acknowledged: 'Resolve' };

// Per-sector configurable detection thresholds, kept in sync via
// 'thresholds_bulk' (on connect), 'thresholds_updated' (admin change), and
// the 'thresholds' field on every telemetry_update tick.
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

const SECTOR_COLORS = {
  hospital: '#3fa796',
  power_grid: '#c9a227',
  bank: '#8b3aff',
};

const GAUGE_RADIUS = 38;
const GAUGE_CIRC = 2 * Math.PI * GAUGE_RADIUS;
const HISTORY_LEN = 30;
const history = {}; // key -> array of risk scores

const SPARK_W = 140;
const SPARK_H = 34;

const grid = document.getElementById('sector-grid');
const logScroll = document.getElementById('log-scroll');
const logEmpty = document.getElementById('log-empty');
const globalStatus = document.getElementById('global-status');
const globalStatusText = document.getElementById('global-status-text');
const filterSectorEl = document.getElementById('filter-sector');
const filterSeverityEl = document.getElementById('filter-severity');
const filterStatusEl = document.getElementById('filter-status');
const exportBtn = document.getElementById('export-csv');
const muteBtn = document.getElementById('mute-btn');
const execOrgRiskEl = document.getElementById('exec-org-risk');
const execStatusLabelEl = document.getElementById('exec-status-label');
const execTopSectorEl = document.getElementById('exec-top-sector');
const execTopSectorScoreEl = document.getElementById('exec-top-sector-score');
const execIncidents24hEl = document.getElementById('exec-incidents-24h');
const auditScroll = document.getElementById('audit-scroll');
const auditEmpty = document.getElementById('audit-empty');

let allLogs = [];
let allAudit = [];
let wasAlertActive = false;
let muted = false;
let audioCtx = null;

// ---------- build sector cards ----------
function buildCards() {
  Object.entries(SECTOR_META).forEach(([key, meta], idx) => {
    const floatWrap = document.createElement('div');
    floatWrap.className = 'card-float';
    floatWrap.style.animationDelay = `${idx * -0.9}s`;
    floatWrap.style.animationDuration = `${3.2 + idx * 0.5}s`;

    const card = document.createElement('div');
    card.className = 'sector-card state-safe card-enter';
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
              stroke="#3fa796"
              stroke-dasharray="0 ${GAUGE_CIRC}"></circle>
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
      ${IS_ANALYST ? `
      <div class="card-actions">
        <button class="simulate-btn" id="simulate-${key}" data-sector="${key}">⚔ Simulate Attack</button>
        <div class="card-actions-row">
          <button class="contain-btn" id="contain-${key}" data-sector="${key}">🛡 Contain</button>
          <button class="fp-btn" id="fp-${key}" data-sector="${key}">✕ False Positive</button>
        </div>
      </div>` : ''}
    `;
    history[key] = [];
    floatWrap.appendChild(card);
    grid.appendChild(floatWrap);
    attachTilt(card, floatWrap);

    if (!IS_ANALYST) return;

    const simulateBtn = card.querySelector(`#simulate-${key}`);
    attachMagnetic(simulateBtn, 10);
    simulateBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      socket.emit('trigger_attack', { sector: key });
      const btn = e.currentTarget;
      btn.textContent = '⚔ Triggered…';
      btn.disabled = true;
      setTimeout(() => { btn.textContent = '⚔ Simulate Attack'; btn.disabled = false; }, 4000);
    });

    const containBtn = card.querySelector(`#contain-${key}`);
    containBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      socket.emit('contain_sector', { sector: key });
      const btn = e.currentTarget;
      btn.textContent = '🛡 Containing…';
      btn.disabled = true;
      setTimeout(() => { btn.textContent = '🛡 Contain'; btn.disabled = false; }, 12000);
    });

    const fpBtn = card.querySelector(`#fp-${key}`);
    fpBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      socket.emit('mark_false_positive', { sector: key });
      const btn = e.currentTarget;
      btn.textContent = '✕ Noted';
      btn.disabled = true;
      setTimeout(() => { btn.textContent = '✕ False Positive'; btn.disabled = false; }, 4000);
    });
  });
}

// ---------- number count-up ----------
function animateNumber(el, from, to, duration = 500) {
  const start = performance.now();
  function step(now) {
    const p = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - p, 3); // ease-out-cubic
    el.textContent = Math.round(from + (to - from) * eased);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ---------- magnetic hover for buttons ----------
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

// ---------- staggered card reveal (called once the boot sequence clears) ----------
function revealCards() {
  document.querySelectorAll('.sector-card.card-enter').forEach((card, idx) => {
    setTimeout(() => card.classList.add('is-in'), idx * 130);
  });
}

// ---------- custom cursor ----------
function initCustomCursor() {
  if (window.matchMedia('(pointer: coarse)').matches || prefersReducedMotion) return;
  const dot = document.getElementById('cursor-dot');
  const ring = document.getElementById('cursor-ring');
  if (!dot || !ring) return;
  document.body.classList.add('has-custom-cursor');

  let mouseX = window.innerWidth / 2, mouseY = window.innerHeight / 2;
  let ringX = mouseX, ringY = mouseY;

  window.addEventListener('mousemove', (e) => {
    mouseX = e.clientX; mouseY = e.clientY;
    dot.style.transform = `translate(${mouseX}px, ${mouseY}px) translate(-50%, -50%)`;
    dot.style.opacity = '1';
    ring.style.opacity = '1';
  });
  document.addEventListener('mouseleave', () => { dot.style.opacity = '0'; ring.style.opacity = '0'; });

  document.addEventListener('mouseover', (e) => {
    if (e.target.closest('button, select, .node-group, .sector-card')) ring.classList.add('is-active');
  });
  document.addEventListener('mouseout', (e) => {
    if (e.target.closest('button, select, .node-group, .sector-card')) ring.classList.remove('is-active');
  });

  (function loop() {
    ringX += (mouseX - ringX) * 0.18;
    ringY += (mouseY - ringY) * 0.18;
    ring.style.transform = `translate(${ringX}px, ${ringY}px) translate(-50%, -50%)`;
    requestAnimationFrame(loop);
  })();
}

// ---------- ambient sector-network particle field ----------
function initParticleField() {
  const canvas = document.getElementById('particle-canvas');
  if (!canvas || prefersReducedMotion || window.matchMedia('(pointer: coarse)').matches) return;
  const ctx = canvas.getContext('2d');
  const COUNT = 46;
  const MAX_DIST = 130;
  let w, h, particles, running = true;

  function resize() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
  }
  function makeParticles() {
    particles = Array.from({ length: COUNT }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
    }));
  }
  resize();
  makeParticles();
  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', () => {
    running = !document.hidden;
    if (running) requestAnimationFrame(tick);
  });

  function tick() {
    if (!running) return;
    ctx.clearRect(0, 0, w, h);
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > w) p.vx *= -1;
      if (p.y < 0 || p.y > h) p.vy *= -1;
    });
    for (let i = 0; i < particles.length; i++) {
      const a = particles[i];
      ctx.fillStyle = 'rgba(201,162,39,0.55)';
      ctx.beginPath();
      ctx.arc(a.x, a.y, 1.4, 0, Math.PI * 2);
      ctx.fill();
      for (let j = i + 1; j < particles.length; j++) {
        const b = particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < MAX_DIST) {
          ctx.strokeStyle = `rgba(63,167,150,${0.12 * (1 - dist / MAX_DIST)})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(tick);
  }
  tick();
}

// ---------- scroll reveal for lower panels ----------
function initScrollReveal() {
  const els = document.querySelectorAll('.reveal');
  if (!els.length) return;
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        obs.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15 });
  els.forEach(el => obs.observe(el));
}

// ---------- boot sequence ----------
const BOOT_LINES = [
  'ESTABLISHING SECURE UPLINK…',
  'LOADING SECTOR BASELINES — HOSPITAL / POWER GRID / BANK',
  'CALIBRATING ANOMALY MODELS…',
  'SENTINEL EYE ONLINE'
];
function runBootSequence() {
  const lineEl = document.getElementById('boot-line');
  const fillEl = document.getElementById('boot-bar-fill');
  const preloader = document.getElementById('preloader');
  if (!lineEl || !preloader || !fillEl) { revealCards(); return; }

  const stepDelay = prefersReducedMotion ? 0 : 620;
  const hideDelay = prefersReducedMotion ? 0 : 500;
  let i = 0;
  function step() {
    lineEl.innerHTML = `${BOOT_LINES[i]}<span class="caret"></span>`;
    fillEl.style.width = `${((i + 1) / BOOT_LINES.length) * 100}%`;
    i++;
    if (i < BOOT_LINES.length) {
      setTimeout(step, stepDelay);
    } else {
      setTimeout(() => {
        preloader.classList.add('is-hidden');
        revealCards();
      }, hideDelay);
    }
  }
  step();

  // safety net: never let a preloader failure hide the dashboard permanently
  setTimeout(() => {
    if (!preloader.classList.contains('is-hidden')) {
      preloader.classList.add('is-hidden');
      revealCards();
    }
  }, 5000);
}

// ---------- traveling pulse along active siege-map edges ----------
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
    if (!line || !pulse) return;
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

// ---------- sparkline ----------
function updateSparkline(key, score) {
  const arr = history[key];
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
  line.setAttribute('stroke', colorForScore(arr[arr.length - 1], key));
}

// ---------- 3D tilt on mouse move (layered on top of continuous float) ----------
function attachTilt(card, floatWrap) {
  const maxTilt = 10;
  floatWrap.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    floatWrap.classList.add('is-hovering');
    card.style.transform = `rotateY(${x * maxTilt}deg) rotateX(${-y * maxTilt}deg) translateZ(24px)`;
  });
  floatWrap.addEventListener('mouseleave', () => {
    floatWrap.classList.remove('is-hovering');
    card.style.transform = 'rotateY(0deg) rotateX(0deg) translateZ(0)';
  });
}

// ---------- gauge + card state ----------
// Both take an optional `sector` so card color/state reflect that sector's
// own configurable thresholds rather than one hardcoded cutoff for everyone.
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
function badgeText(state) {
  return state === 'danger' ? 'Anomaly' : state === 'warn' ? 'Elevated' : 'Secure';
}

function updateCard(key, data) {
  const score = Math.round(data.risk_score);
  const state = stateForScore(score, key);
  const color = colorForScore(score, key);

  const card = document.getElementById(`card-${key}`);
  card.classList.remove('state-safe', 'state-warn', 'state-danger');
  card.classList.add(`state-${state}`);

  const riskEl = document.getElementById(`risk-${key}`);
  const prevScore = parseInt(riskEl.textContent, 10);
  if (!Number.isNaN(prevScore) && prevScore !== score) {
    animateNumber(riskEl, prevScore, score);
    riskEl.classList.remove('is-updating');
    void riskEl.offsetWidth; // restart the pop animation
    riskEl.classList.add('is-updating');
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
  badge.textContent = badgeText(state);

  const sourceBadge = document.getElementById(`source-${key}`);
  if (sourceBadge) {
    if (data.data_source === 'replay') {
      sourceBadge.textContent = '⏺ REPLAY';
      sourceBadge.title = 'Driven by recorded/real telemetry (data/*.csv), not synthetic generation';
      sourceBadge.style.display = 'inline-block';
    } else {
      sourceBadge.style.display = 'none';
    }
  }

  updateSparkline(key, score);

  const factorEl = document.getElementById(`factor-${key}`);
  if (IS_EXEC) {
    // Executives get a plain-English read, not raw z-score/metric jargon.
    factorEl.innerHTML = score >= 75 ? 'Status: <b>Critical — under active review</b>'
      : score >= 40 ? 'Status: <b>Elevated — being monitored</b>'
      : 'Status: <b>Normal</b>';
  } else {
    const factorName = (data.top_factor || '').replace(/_/g, ' ');
    factorEl.innerHTML =
      `Top factor: <b>${factorName}</b> · ${data.metrics ? data.metrics[data.top_factor] : ''}`;
  }

  const attackRow = document.getElementById(`attack-type-${key}`);
  if (data.contained) {
    attackRow.innerHTML = `<span class="attack-chip contained">🛡 Contained — risk suppressed</span>`;
  } else if (data.predicted_attack_type) {
    const label = ATTACK_TYPE_LABEL[data.predicted_attack_type] || data.predicted_attack_type;
    const pct = Math.round((data.attack_confidence || 0) * 100);
    if (IS_EXEC) {
      // Skip the MITRE technique ID for execs — keep the plain label + confidence only.
      attackRow.innerHTML = `<span class="attack-chip">⚠ ${label} <em>${pct}% match</em></span>`;
    } else {
      const mitre = MITRE_MAPPING[data.predicted_attack_type];
      const mitreTag = mitre ? `<span class="mitre-tag" title="${mitre.technique_name}">${mitre.technique_id}</span>` : '';
      attackRow.innerHTML = `<span class="attack-chip">⚠ ${label} <em>${pct}% match</em></span>${mitreTag}`;
    }
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

// ---------- siege map ----------
function resetSiegeMap() {
  document.querySelectorAll('.edge').forEach(e => e.classList.remove('active'));
  document.querySelectorAll('.node-group').forEach(n => n.classList.remove('danger'));
}
function updatePropagation(propagation, sectors) {
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

// ---------- log ----------
const SECTOR_LABEL = { hospital: 'Hospital', power_grid: 'Power Grid', bank: 'Bank' };

function addLogEntries(entries) {
  if (!entries || entries.length === 0) return;
  allLogs.push(...entries);
  renderLogs();
}

function getFilteredLogs() {
  // Executives don't get the filter dropdowns (removed from the DOM for a
  // simpler "briefing" view) — they always see high-severity items only.
  const sectorFilter = filterSectorEl ? filterSectorEl.value : 'all';
  const severityFilter = filterSeverityEl ? filterSeverityEl.value : (IS_EXEC ? 'high' : 'all');
  const statusFilter = filterStatusEl ? filterStatusEl.value : 'all';
  return allLogs.filter(e =>
    (sectorFilter === 'all' || e.sector === sectorFilter) &&
    (severityFilter === 'all' || e.severity === severityFilter) &&
    (statusFilter === 'all' || e.status === statusFilter)
  );
}

function statusBadge(entry) {
  if (!entry.status) return '';
  return `<span class="status-badge status-${entry.status}">${STATUS_LABEL[entry.status] || entry.status}</span>`;
}

function mitreTagFor(entry) {
  if (!entry.mitre_id) return '';
  return `<span class="mitre-tag" title="${entry.mitre_label || ''}">${entry.mitre_id}</span>`;
}

function triageActionsFor(entry) {
  // Only genuine anomalies carry a `status` — propagation/manual/admin log
  // lines aren't part of the triage queue. Only analysts act on alerts.
  if (!IS_ANALYST || !entry.status || entry.id == null) return '';
  const buttons = [];
  const nextStatus = STATUS_NEXT[entry.status];
  if (nextStatus) {
    buttons.push(`<button class="triage-btn" data-id="${entry.id}" data-status="${nextStatus}">${STATUS_NEXT_LABEL[entry.status]}</button>`);
  }
  if (entry.status !== 'new') {
    buttons.push(`<button class="triage-btn reopen" data-id="${entry.id}" data-status="new">Reopen</button>`);
  }
  return buttons.length ? `<div class="triage-actions">${buttons.join('')}</div>` : '';
}

function renderLogs() {
  const filtered = getFilteredLogs();
  logScroll.innerHTML = '';

  if (filtered.length === 0) {
    logEmpty.style.display = 'block';
    logScroll.appendChild(logEmpty);
    return;
  }
  logEmpty.style.display = 'none';

  filtered.slice(-60).forEach(entry => {
    const div = document.createElement('div');
    div.className = `log-entry ${entry.severity === 'high' ? 'high' : ''} ${entry.status ? 'is-alert' : ''}`;
    if (entry.id != null) div.dataset.logId = entry.id;
    div.innerHTML = `
      <div class="log-entry-row">
        <span class="time">${entry.time}</span>
        <span class="sector-tag">${SECTOR_LABEL[entry.sector] || entry.sector}</span>
        ${mitreTagFor(entry)}
        ${statusBadge(entry)}
      </div>
      <span class="msg">${entry.message}</span>
      ${triageActionsFor(entry)}`;
    logScroll.appendChild(div);
  });

  if (IS_ANALYST) {
    logScroll.querySelectorAll('.triage-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = parseInt(btn.dataset.id, 10);
        const status = btn.dataset.status;
        socket.emit('update_alert_status', { id, status });
        btn.disabled = true;
      });
    });
  }
}

function applyAlertStatusUpdate({ id, status }) {
  const entry = allLogs.find(e => e.id === id);
  if (!entry) return;
  entry.status = status;
  renderLogs();
}

function downloadCSV() {
  const rows = getFilteredLogs();
  const header = ['time', 'sector', 'severity', 'message', 'status', 'mitre_id'];
  const csvLines = [header.join(',')];
  rows.forEach(r => {
    const line = [
      r.time, r.sector, r.severity, `"${r.message.replace(/"/g, '""')}"`,
      r.status || '', r.mitre_id || '',
    ].join(',');
    csvLines.push(line);
  });
  const blob = new Blob([csvLines.join('\n')], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `kavach_incident_log_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

if (filterSectorEl) filterSectorEl.addEventListener('change', renderLogs);
if (filterSeverityEl) filterSeverityEl.addEventListener('change', renderLogs);
if (filterStatusEl) filterStatusEl.addEventListener('change', renderLogs);
exportBtn.addEventListener('click', downloadCSV);

// ---------- executive summary ----------
function updateExecSummary(summary) {
  if (!SHOW_EXEC_SUMMARY || !summary || !execOrgRiskEl) return;

  animateNumber(execOrgRiskEl, parseFloat(execOrgRiskEl.textContent) || 0, summary.org_risk);
  execStatusLabelEl.textContent = summary.status_label;
  execStatusLabelEl.className = 'exec-metric-status ' + (
    summary.org_risk >= 75 ? 'exec-status-danger' :
    summary.org_risk >= 45 ? 'exec-status-warn' : 'exec-status-safe'
  );

  execTopSectorEl.textContent = summary.top_sector_label || '—';
  execTopSectorScoreEl.textContent = `Risk score: ${summary.top_sector_score}/100`;

  execIncidents24hEl.textContent = summary.incidents_24h;

  updateExecBriefing(summary);
}

const execBriefingEl = document.getElementById('exec-briefing');
function updateExecBriefing(summary) {
  if (!execBriefingEl) return;
  let text;
  if (summary.org_risk >= 75) {
    text = `⚠ Critical: ${summary.top_sector_label} is under active threat (risk ${summary.top_sector_score}/100). The security team has been alerted and is responding.`;
  } else if (summary.org_risk >= 45) {
    text = `Elevated risk in ${summary.top_sector_label} (${summary.top_sector_score}/100) — being actively monitored, no action needed from you right now.`;
  } else {
    text = `All sectors nominal. ${summary.incidents_24h} incident${summary.incidents_24h === 1 ? '' : 's'} handled in the last 24 hours.`;
  }
  execBriefingEl.textContent = text;
}

// ---------- audit trail ----------
const AUDIT_ACTION_ICON = {
  'Triggered attack simulation': '⚔',
  'Contained sector': '🛡',
  'Marked false positive': '✕',
  'Created user': '👤',
  'Deleted user': '🗑',
  'Reset password': '🔑',
  'Updated detection thresholds': '🎚',
  'Acknowledged alert': '👁',
  'Resolved alert': '✅',
  'Reopened alert': '↩',
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
    const sectorTag = entry.sector ? `<span class="sector-tag">${SECTOR_LABEL[entry.sector] || entry.sector}</span>` : '';
    const detail = entry.detail ? ` — ${entry.detail}` : '';
    const div = document.createElement('div');
    div.className = 'audit-entry';
    div.innerHTML = `
      <span class="time">${entry.time}</span>
      <span class="audit-actor">${icon} ${entry.actor} <span class="audit-role">(${entry.role})</span></span>
      ${sectorTag}
      <span class="msg">${entry.action}${detail}</span>`;
    auditScroll.appendChild(div);
  });
}

function addAuditEntries(entries) {
  if (!entries || entries.length === 0) return;
  allAudit.push(...entries);
  renderAudit();
}
// Initial audit history arrives via the 'audit_log' socket event on connect
// (same pattern as 'log_history') — no separate REST fetch needed here.

// ---------- audio alert ----------
function ensureAudioCtx() {
  if (!audioCtx) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    audioCtx = new Ctx();
  }
  if (audioCtx.state === 'suspended') audioCtx.resume();
  return audioCtx;
}

function playAlertTone() {
  if (muted) return;
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

muteBtn.addEventListener('click', () => {
  muted = !muted;
  muteBtn.classList.toggle('is-muted', muted);
  muteBtn.textContent = muted ? '🔇' : '🔊';
  if (!muted) ensureAudioCtx();
});

// ---------- incident report link ----------
const reportSectorEl = document.getElementById('report-sector');
const reportBtn = document.getElementById('report-btn');
const reportBtnPdf = document.getElementById('report-btn-pdf');
function updateReportLink() {
  if (!reportSectorEl) return;
  if (reportBtn) reportBtn.href = `/report/${reportSectorEl.value}`;
  if (reportBtnPdf) reportBtnPdf.href = `/report/${reportSectorEl.value}/pdf`;
}
if (reportSectorEl) {
  reportSectorEl.addEventListener('change', updateReportLink);
  updateReportLink();
}

// ---------- historical risk chart ----------
let historyChart = null;
function initHistoryChart() {
  const canvas = document.getElementById('history-chart');
  if (!canvas || typeof Chart === 'undefined') return;

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

  historyChart = new Chart(canvas.getContext('2d'), {
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
          backgroundColor: '#131826',
          titleColor: '#e8e6de',
          bodyColor: '#e8e6de',
          borderColor: 'rgba(201,162,39,0.3)',
          borderWidth: 1,
        },
      },
    },
  });

  const legend = document.getElementById('history-legend');
  if (legend) {
    legend.innerHTML = Object.entries(SECTOR_META).map(([key, meta]) =>
      `<span class="legend-item"><span class="legend-dot" style="background:${SECTOR_COLORS[key]}"></span>${meta.label}</span>`
    ).join('');
  }

  // seed with persisted history
  Object.keys(SECTOR_META).forEach(key => {
    fetch(`/api/history/${key}`)
      .then(r => r.json())
      .then(points => {
        if (!Array.isArray(points) || !historyChart) return;
        const ds = historyChart.data.datasets.find(d => d._sector === key);
        if (!ds) return;
        ds.data = points.map(p => p.risk_score);
        if (historyChart.data.labels.length < points.length) {
          historyChart.data.labels = points.map((_, i) => i);
        }
        historyChart.update('none');
      })
      .catch(() => {});
  });
}

function pushHistoryPoint(sectors) {
  if (!historyChart) return;
  historyChart.data.labels.push(historyChart.data.labels.length);
  if (historyChart.data.labels.length > 120) historyChart.data.labels.shift();
  historyChart.data.datasets.forEach(ds => {
    const val = sectors[ds._sector] ? sectors[ds._sector].risk_score : null;
    ds.data.push(val);
    if (ds.data.length > 120) ds.data.shift();
  });
  historyChart.update('none');
}

// ---------- global status ----------
function updateGlobalStatus(sectors) {
  const anyDanger = Object.entries(sectors).some(([key, s]) => stateForScore(s.risk_score, key) === 'danger');
  if (anyDanger) {
    globalStatus.classList.add('alert');
    globalStatusText.textContent = 'THREAT ACTIVE';
    if (!wasAlertActive) playAlertTone();
    wasAlertActive = true;
  } else {
    globalStatus.classList.remove('alert');
    globalStatusText.textContent = 'MONITORING';
    wasAlertActive = false;
  }
}

// ---------- init ----------
buildCards();
buildEdgePulses();
initCustomCursor();
initParticleField();
initScrollReveal();
attachMagnetic(muteBtn, 8);
attachMagnetic(exportBtn, 8);
runBootSequence();
requestAnimationFrame(animatePulses);
initHistoryChart();

// ---------- socket wiring ----------
const socket = io();

socket.on('telemetry_update', (payload) => {
  if (payload.thresholds) applyThresholds(payload.thresholds);
  Object.entries(payload.sectors).forEach(([key, data]) => updateCard(key, data));
  updatePropagation(payload.propagation, payload.sectors);
  updateGlobalStatus(payload.sectors);
  pushHistoryPoint(payload.sectors);
  if (payload.new_log) addLogEntries(payload.new_log);
  if (payload.exec_summary) updateExecSummary(payload.exec_summary);
});

socket.on('log_history', (payload) => {
  addLogEntries(payload.log);
});

socket.on('audit_log', (payload) => {
  addAuditEntries(payload.entries);
});

socket.on('session_info', () => { /* role already rendered server-side */ });

socket.on('thresholds_bulk', (payload) => {
  applyThresholds(payload.thresholds);
});

socket.on('thresholds_updated', (payload) => {
  applyThresholds({ [payload.sector]: payload });
});

socket.on('alert_status_updated', (payload) => {
  applyAlertStatusUpdate(payload);
});

// ---------- demo reset ----------
socket.on('demo_reset', () => {
  allLogs.length = 0;
  allAudit.length = 0;
  renderLogs();
  renderAudit();
});

// ---------- admin quick-panel ----------
if (IS_ADMIN) {
  fetch('/api/admin/summary')
    .then(r => r.json())
    .then(data => {
      const totalEl = document.getElementById('admin-total-users');
      const breakdownEl = document.getElementById('admin-role-breakdown');
      const thresholdListEl = document.getElementById('admin-threshold-list');
      if (totalEl) totalEl.textContent = data.total_users;
      if (breakdownEl) {
        const parts = Object.entries(data.role_counts).map(([role, count]) => `${count} ${role}`);
        breakdownEl.textContent = parts.join(' · ');
      }
      if (thresholdListEl && data.thresholds) {
        thresholdListEl.innerHTML = Object.entries(data.thresholds).map(([sector, t]) => {
          const label = SECTOR_LABEL[sector] || sector;
          return `<div class="admin-threshold-row"><span>${label}</span><span>Alert ${t.alert_threshold} · Critical ${t.critical_threshold}</span></div>`;
        }).join('');
      }
    })
    .catch(() => {
      const thresholdListEl = document.getElementById('admin-threshold-list');
      if (thresholdListEl) thresholdListEl.textContent = 'Unable to load — check /admin panel.';
    });
}