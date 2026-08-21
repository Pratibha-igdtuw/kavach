/**
 * KAVACH Case Management Frontend
 * 
 * Handles:
 *   - Incident list/detail view switching
 *   - Creating/updating/closing incidents
 *   - Adding alerts to incidents
 *   - Linking incidents (attack chains, related events)
 *   - Comment thread management
 *   - Timeline view
 *   - Real-time socket updates
 * 
 * Add this to your templates and reference it in the main dashboard script.
 */

class CaseManagementUI {
  constructor(socket) {
    this.socket = socket;
    this.currentIncidentId = null;
    this.incidents = [];
    this.currentIncident = null;
    
    this.init();
  }
  
  init() {
    // View switching
    document.getElementById('btn-back-to-list')?.addEventListener('click', () => this.showListView());
    
    // Create incident modal
    document.getElementById('btn-create-incident')?.addEventListener('click', () => this.showCreateModal());
    document.getElementById('btn-modal-create')?.addEventListener('click', () => this.createIncident());
    document.getElementById('btn-modal-cancel')?.addEventListener('click', () => this.hideCreateModal());
    
    // Close incident modal
    document.getElementById('btn-close-case')?.addEventListener('click', () => this.showCloseModal());
    document.getElementById('btn-modal-close')?.addEventListener('click', () => this.closeIncident());
    document.getElementById('btn-modal-close-cancel')?.addEventListener('click', () => this.hideCloseModal());
    
    // Delete incident
    document.getElementById('btn-delete-case')?.addEventListener('click', () => {
      if (confirm('Are you sure you want to delete this case?')) {
        this.deleteIncident();
      }
    });
    
    // Filters
    document.getElementById('filter-status')?.addEventListener('change', () => this.loadIncidents());
    document.getElementById('filter-sector')?.addEventListener('change', () => this.loadIncidents());
    
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
    });
    
    // Alert linking
    document.getElementById('btn-add-alert')?.addEventListener('click', () => this.addAlertToIncident());
    
    // Incident linking
    document.getElementById('btn-link-incident')?.addEventListener('click', () => this.linkIncidents());
    
    // Comments
    document.getElementById('btn-add-comment')?.addEventListener('click', () => this.addComment());
    
    // Socket listeners
    this.setupSocketListeners();
    
    // Load incidents on init
    this.loadIncidents();
  }
  
  // ========================================================================
  // VIEW MANAGEMENT
  // ========================================================================
  
  showListView() {
    document.getElementById('case-list-view').style.display = 'block';
    document.getElementById('case-detail-view').style.display = 'none';
    this.currentIncidentId = null;
    this.loadIncidents();
  }
  
  showDetailView(incidentId) {
    this.currentIncidentId = incidentId;
    document.getElementById('case-list-view').style.display = 'none';
    document.getElementById('case-detail-view').style.display = 'block';
    this.loadIncidentDetail(incidentId);
  }
  
  switchTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update content
    document.querySelectorAll('.case-tab-content').forEach(tab => tab.classList.remove('active'));
    document.getElementById(`tab-${tabName}`).classList.add('active');
  }
  
  // ========================================================================
  // INCIDENT LIST
  // ========================================================================
  
  async loadIncidents() {
    const status = document.getElementById('filter-status')?.value || 'open';
    const sector = document.getElementById('filter-sector')?.value || '';
    
    try {
      const params = new URLSearchParams();
      if (status) params.append('status', status);
      if (sector) params.append('sector', sector);
      
      const response = await fetch(`/incidents?${params}`);
      const data = await response.json();
      
      this.incidents = data.incidents || [];
      const stats = data.stats || {};
      
      // Update stats
      document.getElementById('stat-open').textContent = stats.open || '0';
      document.getElementById('stat-closed').textContent = stats.closed || '0';
      document.getElementById('stat-avg-time').textContent = 
        stats.avg_time_to_close_seconds ? this.formatSeconds(stats.avg_time_to_close_seconds) : '—';
      
      // Render list
      this.renderIncidentList();
    } catch (err) {
      console.error('Error loading incidents:', err);
    }
  }
  
  renderIncidentList() {
    const listContainer = document.getElementById('case-list-items');
    if (!listContainer) return;
    
    if (this.incidents.length === 0) {
      listContainer.innerHTML = '<p style="color: #999; text-align: center; padding: 40px;">No incidents found</p>';
      return;
    }
    
    listContainer.innerHTML = this.incidents.map(incident => `
      <div class="case-item" onclick="caseUI.showDetailView(${incident.id})">
        <div class="case-item-header">
          <span class="case-item-title">#${incident.id}: ${incident.title}</span>
          <span class="case-item-badge badge-${incident.status}">${incident.status}</span>
        </div>
        <div class="case-item-meta">
          <span>${incident.sector || 'N/A'}</span>
          <span> • Severity: ${incident.severity}</span>
          <span> • Created by ${incident.created_by}</span>
        </div>
      </div>
    `).join('');
  }
  
  // ========================================================================
  // INCIDENT DETAIL
  // ========================================================================
  
  async loadIncidentDetail(incidentId) {
    try {
      const response = await fetch(`/incidents/${incidentId}`);
      const data = await response.json();
      
      this.currentIncident = data.incident;
      
      // Update header
      document.getElementById('detail-title').textContent = `#${data.incident.id}: ${data.incident.title}`;
      document.getElementById('detail-description').textContent = data.incident.description || '';
      document.getElementById('detail-status').value = data.incident.status;
      document.getElementById('detail-severity').value = data.incident.severity;
      document.getElementById('detail-sector').textContent = data.incident.sector || 'N/A';
      document.getElementById('detail-created-by').textContent = data.incident.created_by;
      
      // Update alert count in tab
      document.querySelector('[data-tab="alerts"]').textContent = 
        `Alerts (${data.alerts.length})`;
      
      // Render tabs
      this.renderTimeline(data.timeline);
      this.renderAlerts(data.alerts, data.suggestions);
      this.renderLinks(data.links);
      this.renderComments(data.comments);
      
    } catch (err) {
      console.error('Error loading incident detail:', err);
    }
  }
  
  renderTimeline(events) {
    const container = document.getElementById('timeline-events');
    if (!container) return;
    
    if (!events || events.length === 0) {
      container.innerHTML = '<p style="color: #999;">No events yet</p>';
      return;
    }
    
    container.innerHTML = events.map(event => {
      if (event.type === 'alert') {
        return `
          <div class="timeline-event alert">
            <div class="timeline-time">${new Date(event.ts * 1000).toLocaleString()}</div>
            <div class="timeline-content">
              <strong>🚨 Alert #${event.log_id}</strong><br>
              ${event.message}<br>
              <small>${event.sector} • ${event.severity} • ${event.attack_type || 'Unknown'}</small>
            </div>
          </div>
        `;
      } else if (event.type === 'comment') {
        return `
          <div class="timeline-event comment">
            <div class="timeline-time">${new Date(event.ts * 1000).toLocaleString()}</div>
            <div class="timeline-content">
              <strong>💬 ${event.author}</strong><br>
              ${event.body}
              ${event.edited_ts ? `<br><small>Edited by ${event.edited_by}</small>` : ''}
            </div>
          </div>
        `;
      }
      return '';
    }).join('');
  }
  
  renderAlerts(alerts, suggestions) {
    const container = document.getElementById('case-alerts-list');
    if (!container) return;
    
    // Update suggestion dropdown
    const selectIncident = document.getElementById('select-link-incident');
    if (selectIncident && suggestions) {
      selectIncident.innerHTML = '<option value="">-- Select a case --</option>' +
        suggestions.map(s => `<option value="${s.id}">#${s.id}: ${s.title}</option>`).join('');
    }
    
    if (!alerts || alerts.length === 0) {
      container.innerHTML = '<p style="color: #999;">No alerts linked</p>';
      return;
    }
    
    container.innerHTML = alerts.map(alert => `
      <div class="alert-item">
        <div class="alert-item-info">
          <div class="alert-item-msg">#${alert.id}: ${alert.message}</div>
          <div class="alert-item-meta">
            ${alert.sector} • ${alert.severity} • ${alert.attack_type || 'Unknown'} • 
            ${new Date(alert.ts * 1000).toLocaleString()}
          </div>
        </div>
        <button class="btn btn-danger" onclick="caseUI.removeAlertFromIncident(${this.currentIncidentId}, ${alert.id})">
          Remove
        </button>
      </div>
    `).join('');
  }
  
  renderLinks(links) {
    const container = document.getElementById('case-links-list');
    if (!container) return;
    
    const allLinks = [...(links.outgoing || []), ...(links.incoming || [])];
    
    if (!allLinks || allLinks.length === 0) {
      container.innerHTML = '<p style="color: #999;">No related incidents</p>';
      return;
    }
    
    container.innerHTML = allLinks.map(link => `
      <div class="link-item">
        <strong>#${link.incident_id_b || link.incident_id_a}: ${link.title}</strong>
        <br>
        <span class="link-relation">${link.relation_type.toUpperCase()}</span>
        ${link.notes ? `<br><small>${link.notes}</small>` : ''}
        <br>
        <button class="btn btn-danger" style="font-size: 11px; padding: 4px 8px; margin-top: 6px;"
                onclick="caseUI.unlinkIncidents(${link.incident_id_a}, ${link.incident_id_b}, '${link.relation_type}')">
          Unlink
        </button>
      </div>
    `).join('');
  }
  
  renderComments(comments) {
    const container = document.getElementById('case-comments-list');
    if (!container) return;
    
    if (!comments || comments.length === 0) {
      container.innerHTML = '<p style="color: #999;">No comments yet</p>';
      return;
    }
    
    container.innerHTML = comments.map(comment => `
      <div class="comment">
        <div class="comment-header">
          <span class="comment-author">${comment.author}</span>
          <span class="comment-time">${new Date(comment.ts * 1000).toLocaleString()}</span>
        </div>
        <div class="comment-body">${comment.body}</div>
        ${comment.edited_ts ? `<small style="color: #888;">Edited ${new Date(comment.edited_ts * 1000).toLocaleString()}</small>` : ''}
        <br>
        <button class="btn btn-danger" style="font-size: 11px; padding: 4px 8px; margin-top: 6px;"
                onclick="caseUI.deleteComment(${this.currentIncidentId}, ${comment.id})">
          Delete
        </button>
      </div>
    `).join('');
  }
  
  // ========================================================================
  // INCIDENT CRUD
  // ========================================================================
  
  showCreateModal() {
    document.getElementById('modal-create-incident').style.display = 'flex';
  }
  
  hideCreateModal() {
    document.getElementById('modal-create-incident').style.display = 'none';
    // Clear form
    document.getElementById('modal-incident-title').value = '';
    document.getElementById('modal-incident-description').value = '';
    document.getElementById('modal-incident-sector').value = '';
    document.getElementById('modal-incident-severity').value = 'medium';
  }
  
  async createIncident() {
    const title = document.getElementById('modal-incident-title').value.trim();
    const description = document.getElementById('modal-incident-description').value.trim();
    const sector = document.getElementById('modal-incident-sector').value;
    const severity = document.getElementById('modal-incident-severity').value;
    
    if (!title) {
      alert('Title is required');
      return;
    }
    
    try {
      const response = await fetch('/incidents/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, description, sector, severity }),
      });
      
      if (response.ok) {
        const data = await response.json();
        this.hideCreateModal();
        this.loadIncidents();
        this.showDetailView(data.incident_id);
      } else {
        alert('Error creating incident');
      }
    } catch (err) {
      console.error('Error creating incident:', err);
    }
  }
  
  showCloseModal() {
    document.getElementById('modal-close-incident').style.display = 'flex';
  }
  
  hideCloseModal() {
    document.getElementById('modal-close-incident').style.display = 'none';
    document.getElementById('modal-root-cause').value = '';
    document.getElementById('modal-resolution').value = '';
  }
  
  async closeIncident() {
    const rootCause = document.getElementById('modal-root-cause').value.trim();
    const resolution = document.getElementById('modal-resolution').value.trim();
    
    try {
      const response = await fetch(`/incidents/${this.currentIncidentId}/close`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ root_cause: rootCause, resolution_summary: resolution }),
      });
      
      if (response.ok) {
        this.hideCloseModal();
        this.loadIncidentDetail(this.currentIncidentId);
      } else {
        alert('Error closing incident');
      }
    } catch (err) {
      console.error('Error closing incident:', err);
    }
  }
  
  async deleteIncident() {
    try {
      const response = await fetch(`/incidents/${this.currentIncidentId}`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        this.showListView();
      } else {
        alert('Error deleting incident');
      }
    } catch (err) {
      console.error('Error deleting incident:', err);
    }
  }
  
  // ========================================================================
  // ALERT LINKING
  // ========================================================================
  
  async addAlertToIncident() {
    const logId = parseInt(document.getElementById('input-alert-id').value);
    
    if (!logId) {
      alert('Enter a valid alert ID');
      return;
    }
    
    try {
      const response = await fetch(`/incidents/${this.currentIncidentId}/alerts/add`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_id: logId }),
      });
      
      if (response.ok) {
        document.getElementById('input-alert-id').value = '';
        this.loadIncidentDetail(this.currentIncidentId);
      } else {
        const err = await response.json();
        alert(err.error || 'Error adding alert');
      }
    } catch (err) {
      console.error('Error adding alert:', err);
    }
  }
  
  async removeAlertFromIncident(incidentId, logId) {
    try {
      const response = await fetch(`/incidents/${incidentId}/alerts/${logId}/remove`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        this.loadIncidentDetail(incidentId);
      } else {
        alert('Error removing alert');
      }
    } catch (err) {
      console.error('Error removing alert:', err);
    }
  }
  
  // ========================================================================
  // INCIDENT LINKING
  // ========================================================================
  
  async linkIncidents() {
    const targetId = parseInt(document.getElementById('select-link-incident').value);
    const relationType = document.getElementById('select-relation-type').value;
    const notes = document.getElementById('input-link-notes').value.trim();
    
    if (!targetId) {
      alert('Select a case to link');
      return;
    }
    
    try {
      const response = await fetch(`/incidents/${this.currentIncidentId}/links`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: targetId,
          relation_type: relationType,
          notes: notes,
        }),
      });
      
      if (response.ok) {
        document.getElementById('select-link-incident').value = '';
        document.getElementById('input-link-notes').value = '';
        this.loadIncidentDetail(this.currentIncidentId);
      } else {
        alert('Error linking incidents');
      }
    } catch (err) {
      console.error('Error linking incidents:', err);
    }
  }
  
  async unlinkIncidents(incidentAId, incidentBId, relationType) {
    try {
      const response = await fetch(
        `/incidents/${incidentAId}/links/${incidentBId}/${relationType}`,
        { method: 'DELETE' }
      );
      
      if (response.ok) {
        this.loadIncidentDetail(this.currentIncidentId);
      } else {
        alert('Error unlinking incidents');
      }
    } catch (err) {
      console.error('Error unlinking incidents:', err);
    }
  }
  
  // ========================================================================
  // COMMENTS
  // ========================================================================
  
  async addComment() {
    const body = document.getElementById('input-new-comment').value.trim();
    
    if (!body) {
      alert('Enter a comment');
      return;
    }
    
    try {
      const response = await fetch(`/incidents/${this.currentIncidentId}/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ body }),
      });
      
      if (response.ok) {
        document.getElementById('input-new-comment').value = '';
        this.loadIncidentDetail(this.currentIncidentId);
      } else {
        alert('Error adding comment');
      }
    } catch (err) {
      console.error('Error adding comment:', err);
    }
  }
  
  async deleteComment(incidentId, commentId) {
    try {
      const response = await fetch(`/incidents/${incidentId}/comments/${commentId}`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        this.loadIncidentDetail(incidentId);
      } else {
        alert('Error deleting comment');
      }
    } catch (err) {
      console.error('Error deleting comment:', err);
    }
  }
  
  // ========================================================================
  // SOCKET LISTENERS
  // ========================================================================
  
  setupSocketListeners() {
    if (!this.socket) return;
    
    this.socket.on('incident_created', (data) => {
      this.loadIncidents();
    });
    
    this.socket.on('incident_updated', (data) => {
      if (this.currentIncidentId === data.incident_id) {
        this.loadIncidentDetail(this.currentIncidentId);
      }
      this.loadIncidents();
    });
    
    this.socket.on('incident_closed', (data) => {
      if (this.currentIncidentId === data.incident_id) {
        this.loadIncidentDetail(this.currentIncidentId);
      }
      this.loadIncidents();
    });
    
    this.socket.on('incident_deleted', (data) => {
      if (this.currentIncidentId === data.incident_id) {
        this.showListView();
      } else {
        this.loadIncidents();
      }
    });
    
    this.socket.on('alert_added_to_incident', (data) => {
      if (this.currentIncidentId === data.incident_id) {
        this.loadIncidentDetail(this.currentIncidentId);
      }
    });
    
    this.socket.on('comment_added', (data) => {
      if (this.currentIncidentId === data.incident_id) {
        this.loadIncidentDetail(this.currentIncidentId);
      }
    });
  }
  
  // ========================================================================
  // UTILITIES
  // ========================================================================
  
  formatSeconds(seconds) {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    return `${Math.round(seconds / 3600)}h`;
  }
}

// Initialize when socket is ready
// In your main dashboard script, call:
// let caseUI = new CaseManagementUI(socket);