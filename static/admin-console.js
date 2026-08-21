(function () {
  const K = window.Kavach;

  // Reveal all panels immediately/robustly -- must run before anything else
  // in this file that could throw (see analyst.js for why).
  K.initScrollReveal();

  const statusList = document.getElementById('system-status-list');
  const roleCountGrid = document.getElementById('role-count-grid');
  const recentActionsList = document.getElementById('recent-actions-list');
  const recentActionsEmpty = document.getElementById('recent-actions-empty');

  const ROLE_COUNT_LABEL = {
    analyst: 'SOC Analysts',
    executive: 'Security Managers',
    admin: 'System Administrators',
  };
  const ACTION_ICON = {
    'Created user': '👤', 'Deleted user': '🗑', 'Reset password': '🔑',
    'Updated detection thresholds': '🎚', 'Reset demo data': '🔄',
  };

  function renderSystemHealth() {
    fetch('/api/admin/system-health').then(r => r.json()).then(data => {
      if (!statusList) return;
      statusList.innerHTML = data.services.map(s => `
        <div class="status-row">
          <div>
            <div class="status-row-name">${s.name}</div>
            <div class="status-row-detail">${s.detail}</div>
          </div>
          <span class="status-chip ${s.status}">${s.status}</span>
        </div>
      `).join('');
    }).catch(() => {
      if (statusList) statusList.innerHTML = `<div class="status-row"><span class="status-row-name">Unable to reach system-health endpoint</span><span class="status-chip ERROR">ERROR</span></div>`;
    });
  }

  function renderSummary() {
    fetch('/api/admin/summary').then(r => r.json()).then(data => {
      if (roleCountGrid) {
        roleCountGrid.innerHTML = Object.entries(data.role_counts).map(([role, count]) => `
          <div class="role-count-card">
            <div class="role-count-value">${count}</div>
            <div class="role-count-label">${ROLE_COUNT_LABEL[role] || role}</div>
          </div>`).join('');
      }
      if (recentActionsList) {
        if (!data.recent_actions || data.recent_actions.length === 0) {
          recentActionsEmpty.style.display = 'block';
          recentActionsList.innerHTML = '';
        } else {
          recentActionsEmpty.style.display = 'none';
          recentActionsList.innerHTML = data.recent_actions.map(entry => {
            const icon = ACTION_ICON[entry.action] || '•';
            const detail = entry.detail ? ` — ${entry.detail}` : '';
            return `<div class="audit-entry">
              <span class="time">${entry.time}</span>
              <span class="audit-actor">${icon} ${entry.actor}</span>
              <span class="msg">${entry.action}${detail}</span>
            </div>`;
          }).join('');
        }
      }
    }).catch(() => {});
  }

  renderSystemHealth();
  renderSummary();
  setInterval(renderSystemHealth, 8000);
  setInterval(renderSummary, 10000);

  // Live-update recent actions / role counts as they happen, without a poll delay.
  const socket = io();
  socket.on('audit_log', () => { renderSummary(); });
})();