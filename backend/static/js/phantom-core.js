/**
 * Dark Knight Phantom SIEM - Core JavaScript
 * Global interactivity and modal functionality
 */

// Base API URL
const API_BASE = '/api/v1';

/**
 * Event Detail Modal Functions
 */
async function showEventDetails(eventId) {
    const modal = document.getElementById('event-modal');
    const body = document.getElementById('event-modal-body');
    
    if (!modal || !body) {
        console.error('Event modal elements not found');
        return;
    }
    
    // Ensure eventId is a number (not a string)
    eventId = parseInt(eventId);
    if (isNaN(eventId)) {
        console.error('Invalid event ID:', eventId);
        alert('Invalid event ID');
        return;
    }
    
    modal.style.display = 'flex';
    body.innerHTML = '<div style="text-align: center; padding: 40px;"><div class="loading-spinner"></div><p style="margin-top: 10px;">Loading...</p></div>';
    
    const url = `${API_BASE}/events/list/${eventId}/`;
    console.log('Fetching event from:', url);
    
    try {
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
            }
        });
        
        console.log('Response status:', response.status, response.statusText);
        
        if (!response.ok) {
            let errorText = 'Unknown error';
            try {
                errorText = await response.text();
            } catch (e) {
                errorText = response.statusText;
            }
            throw new Error(`HTTP ${response.status}: ${errorText.substring(0, 200)}`);
        }
        
        const event = await response.json();
        console.log('Event data received:', event);
        
        if (!event) {
            throw new Error('No event data received');
        }
        
        // Check if we got a list instead of a single event
        if (Array.isArray(event)) {
            if (event.length === 0) {
                throw new Error('Event not found');
            }
            renderEventModal(event[0]);
        } else if (event.id || event.event_id) {
            renderEventModal(event);
        } else {
            throw new Error('Invalid event data format');
        }
    } catch (error) {
        console.error('Error loading event:', error);
        body.innerHTML = `
            <div style="padding: 20px; color: var(--status-critical);">
                <h4>Error loading event</h4>
                <p>${escapeHtml(error.message)}</p>
                <p style="font-size: 12px; color: var(--text-muted); margin-top: 10px;">
                    Event ID: ${eventId}<br>
                    Endpoint: ${url}<br>
                    <button class="btn btn-secondary" onclick="closeEventModal()" style="margin-top: 10px;">Close</button>
                </p>
            </div>
        `;
    }
}

function renderEventModal(event) {
    const body = document.getElementById('event-modal-body');
    
    const timestamp = new Date(event.timestamp).toLocaleString();
    
    // Build clickable field helper
    const clickableField = (label, value, searchType, searchValue) => {
        if (!value || value === '-' || value === '') return '';
        const displayValue = typeof value === 'string' && value.length > 100 ? value.substring(0, 100) + '...' : value;
        const clickable = searchType ? `onclick="pivotSearch('${searchType}', '${String(searchValue || value).replace(/'/g, "\\'")}')" style="cursor: pointer; color: var(--accent-purple); text-decoration: underline;"` : '';
        return `
            <div class="event-field">
                <div class="event-field-label">${label}</div>
                <div class="event-field-value" ${clickable}>${displayValue}</div>
            </div>
        `;
    };
    
    let html = `
        <div class="modal-tabs">
            <button class="tab-btn active" onclick="switchEventTab('overview')">Overview</button>
            <button class="tab-btn" onclick="switchEventTab('user')">User Info</button>
            <button class="tab-btn" onclick="switchEventTab('process')">Process</button>
            <button class="tab-btn" onclick="switchEventTab('network')">Network</button>
            <button class="tab-btn" onclick="switchEventTab('raw')">Raw Data</button>
        </div>
        
        <div id="event-tab-overview" class="tab-content active">
            <div class="event-detail-grid">
                ${clickableField('Event ID', event.event_id, 'event_id', event.event_id)}
                ${clickableField('Timestamp', timestamp)}
                ${clickableField('Hostname', event.hostname, 'hostname', event.hostname)}
                ${clickableField('Channel', event.channel, 'channel', event.channel)}
                ${clickableField('Provider', event.provider_name)}
                ${clickableField('Level', event.level_name)}
                ${clickableField('Task', event.task_name)}
            </div>
            
            <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Message</h4>
            <div class="code-block">${escapeHtml(event.message || 'No message')}</div>
        </div>
        
        <div id="event-tab-user" class="tab-content" style="display: none;">
            <div class="event-detail-grid">
                ${clickableField('User Name', event.user_name, 'user_name', event.user_name)}
                ${clickableField('User Domain', event.user_domain)}
                ${clickableField('User SID', event.user_sid)}
                ${clickableField('Target User', event.target_user_name, 'target_user_name', event.target_user_name)}
                ${clickableField('Target Domain', event.target_user_domain)}
                ${clickableField('Logon Type', event.logon_type_name || event.logon_type)}
                ${clickableField('Logon ID', event.logon_id)}
                ${clickableField('Auth Package', event.authentication_package)}
                ${clickableField('Workstation', event.workstation_name)}
            </div>
        </div>
        
        <div id="event-tab-process" class="tab-content" style="display: none;">
            <div class="event-detail-grid">
                ${clickableField('Process Name', event.process_name, 'process_name', event.process_name)}
                ${clickableField('Process ID', event.process_id)}
                ${clickableField('Process Path', event.process_path)}
                ${clickableField('Parent Process', event.parent_process_name, 'parent_process_name', event.parent_process_name)}
                ${clickableField('Parent PID', event.parent_process_id)}
                ${clickableField('Service Name', event.service_name, 'service_name', event.service_name)}
            </div>
            
            ${event.command_line ? `
                <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Command Line</h4>
                <div class="code-block">${escapeHtml(event.command_line)}</div>
            ` : ''}
            
            ${event.parent_command_line ? `
                <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Parent Command Line</h4>
                <div class="code-block">${escapeHtml(event.parent_command_line)}</div>
            ` : ''}
        </div>
        
        <div id="event-tab-network" class="tab-content" style="display: none;">
            <div class="event-detail-grid">
                ${clickableField('Source IP', event.source_ip, 'source_ip', event.source_ip)}
                ${clickableField('Source Port', event.source_port)}
                ${clickableField('Destination IP', event.destination_ip, 'destination_ip', event.destination_ip)}
                ${clickableField('Destination Port', event.destination_port)}
                ${clickableField('Protocol', event.protocol)}
            </div>
        </div>
        
        <div id="event-tab-raw" class="tab-content" style="display: none;">
            ${event.event_data && Object.keys(event.event_data).length > 0 ? `
                <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Event Data (JSON)</h4>
                <div class="code-block"><pre>${JSON.stringify(event.event_data, null, 2)}</pre></div>
            ` : ''}
            
            ${event.raw_xml ? `
                <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Raw XML</h4>
                <div class="code-block"><pre>${escapeHtml(event.raw_xml.substring(0, 5000))}${event.raw_xml.length > 5000 ? '\n... (truncated)' : ''}</pre></div>
            ` : ''}
        </div>
        
        <div style="margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border-color); display: flex; gap: 8px;">
            <button class="btn btn-primary" onclick="pivotSearch('event_id', '${event.event_id}')">
                <i class="fas fa-search"></i> Find Similar Events
            </button>
            <button class="btn btn-secondary" onclick="runPQLQuery('SEARCH events WHERE event_id = ${event.event_id} LIMIT 100')">
                <i class="fas fa-terminal"></i> Run PQL Query
            </button>
            ${event.hostname ? `<button class="btn btn-secondary" onclick="pivotSearch('hostname', '${event.hostname}')">
                <i class="fas fa-desktop"></i> All Events from ${event.hostname}
            </button>` : ''}
        </div>
    `;
    
    body.innerHTML = html;
}

function switchEventTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.style.display = 'none';
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(`event-tab-${tabName}`).style.display = 'block';
    event.target.classList.add('active');
}

function closeEventModal() {
    document.getElementById('event-modal').style.display = 'none';
}

/**
 * Alert Detail Modal Functions
 */
async function showAlertDetails(alertId) {
    const modal = document.getElementById('alert-modal');
    const body = document.getElementById('alert-modal-body');
    
    modal.style.display = 'flex';
    body.innerHTML = '<div style="text-align: center; padding: 40px;"><div class="loading-spinner"></div><p style="margin-top: 10px;">Loading...</p></div>';
    
    try {
        const response = await fetch(`${API_BASE}/detection/alerts/${alertId}/`);
        if (!response.ok) throw new Error('Failed to load alert');
        
        const alert = await response.json();
        renderAlertModal(alert);
    } catch (error) {
        console.error('Error loading alert:', error);
        body.innerHTML = `<div style="padding: 20px; color: var(--status-critical);">Error loading alert: ${error.message}</div>`;
    }
}

function renderAlertModal(alert) {
    const body = document.getElementById('alert-modal-body');
    const severityClass = alert.severity.toLowerCase();
    const triggeredAt = new Date(alert.triggered_at).toLocaleString();
    
    let html = `
        <div class="alert-detail-header">
            <div>
                <h3 style="margin: 0 0 8px 0;">${escapeHtml(alert.title)}</h3>
                <span class="severity-badge ${severityClass}">${alert.severity}</span>
                <span class="status-badge ${alert.status.toLowerCase()}">${alert.status}</span>
            </div>
            <div style="text-align: right; color: var(--text-muted); font-size: 12px;">
                <div>Triggered: ${triggeredAt}</div>
                <div>Confidence: ${alert.confidence}%</div>
            </div>
        </div>
        
        <div class="event-detail-grid" style="margin-top: 20px;">
            <div class="event-field">
                <div class="event-field-label">Rule</div>
                <div class="event-field-value">${escapeHtml(alert.rule_name || 'Unknown')}</div>
            </div>
            <div class="event-field">
                <div class="event-field-label">Hostname</div>
                <div class="event-field-value" onclick="pivotSearch('hostname', '${alert.hostname}')" style="cursor: pointer; color: var(--accent-purple);">${escapeHtml(alert.hostname)}</div>
            </div>
            ${alert.user_name ? `
            <div class="event-field">
                <div class="event-field-label">User</div>
                <div class="event-field-value" onclick="pivotSearch('user_name', '${alert.user_name}')" style="cursor: pointer; color: var(--accent-purple);">${escapeHtml(alert.user_name)}</div>
            </div>
            ` : ''}
            ${alert.source_ip ? `
            <div class="event-field">
                <div class="event-field-label">Source IP</div>
                <div class="event-field-value" onclick="pivotSearch('source_ip', '${alert.source_ip}')" style="cursor: pointer; color: var(--accent-purple);">${escapeHtml(alert.source_ip)}</div>
            </div>
            ` : ''}
            <div class="event-field">
                <div class="event-field-label">Event Count</div>
                <div class="event-field-value">${alert.event_count}</div>
            </div>
        </div>
        
        <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Description</h4>
        <div class="code-block">${escapeHtml(alert.description)}</div>
        
        ${alert.matched_events_data && alert.matched_events_data.length > 0 ? `
            <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Matched Events (${alert.matched_events_data.length})</h4>
            <div style="max-height: 400px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Event ID</th>
                            <th>Hostname</th>
                            <th>User</th>
                            <th>Message</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${alert.matched_events_data.map(e => `
                            <tr>
                                <td style="font-size: 11px;">${new Date(e.timestamp).toLocaleString()}</td>
                                <td><code>${e.event_id}</code></td>
                                <td>${escapeHtml(e.hostname)}</td>
                                <td>${escapeHtml(e.user_name || '-')}</td>
                                <td style="font-size: 11px; max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml((e.message || '').substring(0, 80))}</td>
                                <td><button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="showEventDetails(${e.id})">View</button></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        ` : ''}
        
        ${alert.evidence ? `
            <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Evidence</h4>
            <div class="code-block"><pre>${JSON.stringify(alert.evidence, null, 2)}</pre></div>
        ` : ''}
    `;
    
    body.innerHTML = html;
}

function closeAlertModal() {
    document.getElementById('alert-modal').style.display = 'none';
}

/**
 * Agent Detail Modal Functions
 */
async function showAgentDetails(agentId) {
    const modal = document.getElementById('agent-modal');
    const body = document.getElementById('agent-modal-body');
    
    modal.style.display = 'flex';
    body.innerHTML = '<div style="text-align: center; padding: 40px;"><div class="loading-spinner"></div><p style="margin-top: 10px;">Loading...</p></div>';
    
    try {
        const response = await fetch(`${API_BASE}/agents/list/${agentId}/`);
        if (!response.ok) throw new Error('Failed to load agent');
        
        const agent = await response.json();
        
        // Also fetch recent events from this agent
        const eventsResponse = await fetch(`${API_BASE}/events/list/?agent_id=${agent.agent_id || agentId}&limit=50`);
        const eventsData = await eventsResponse.json();
        const events = eventsData.results || eventsData;
        
        renderAgentModal(agent, events);
    } catch (error) {
        console.error('Error loading agent:', error);
        body.innerHTML = `<div style="padding: 20px; color: var(--status-critical);">Error loading agent: ${error.message}</div>`;
    }
}

function renderAgentModal(agent, events) {
    const body = document.getElementById('agent-modal-body');
    const isOnline = agent.is_online || agent.status === 'ONLINE';
    const lastHeartbeat = agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : 'Never';
    
    let html = `
        <div class="event-detail-grid">
            <div class="event-field">
                <div class="event-field-label">Hostname</div>
                <div class="event-field-value">${escapeHtml(agent.hostname)}</div>
            </div>
            <div class="event-field">
                <div class="event-field-label">IP Address</div>
                <div class="event-field-value">${escapeHtml(agent.ip_address || '-')}</div>
            </div>
            <div class="event-field">
                <div class="event-field-label">Status</div>
                <div class="event-field-value">
                    <span class="status-dot ${isOnline ? 'online' : 'offline'}"></span>
                    ${isOnline ? 'Online' : 'Offline'}
                </div>
            </div>
            <div class="event-field">
                <div class="event-field-label">Last Heartbeat</div>
                <div class="event-field-value">${lastHeartbeat}</div>
            </div>
            <div class="event-field">
                <div class="event-field-label">OS Type</div>
                <div class="event-field-value">${escapeHtml(agent.os_type || '-')}</div>
            </div>
            <div class="event-field">
                <div class="event-field-label">Server Role</div>
                <div class="event-field-value">${escapeHtml(agent.server_role || 'Workstation')}</div>
            </div>
            <div class="event-field">
                <div class="event-field-label">Events Today</div>
                <div class="event-field-value">${(agent.events_sent_today || 0).toLocaleString()}</div>
            </div>
            <div class="event-field">
                <div class="event-field-label">Total Events</div>
                <div class="event-field-value">${(agent.events_sent_total || agent.events_sent_today || 0).toLocaleString()}</div>
            </div>
        </div>
        
        ${events && events.length > 0 ? `
            <h4 style="margin: 20px 0 10px 0; color: var(--accent-purple);">Recent Events (${events.length})</h4>
            <div style="max-height: 400px; overflow-y: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Event ID</th>
                            <th>Channel</th>
                            <th>Severity</th>
                            <th>Message</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${events.map(e => `
                            <tr>
                                <td style="font-size: 11px;">${new Date(e.timestamp).toLocaleString()}</td>
                                <td><code>${e.event_id}</code></td>
                                <td>${escapeHtml(e.channel || '-')}</td>
                                <td><span class="severity-badge ${((e.severity || 'INFO').toUpperCase()).toLowerCase()}">${(e.severity || 'INFO').toUpperCase()}</span></td>
                                <td style="font-size: 11px; max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml((e.message || '').substring(0, 80))}</td>
                                <td><button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="showEventDetails(${e.id})">View</button></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        ` : '<p style="color: var(--text-muted); margin-top: 20px;">No recent events</p>'}
    `;
    
    body.innerHTML = html;
}

function closeAgentModal() {
    document.getElementById('agent-modal').style.display = 'none';
}

/**
 * Entity Pivot Search - Click any value to search for it
 */
function pivotSearch(field, value) {
    if (!value || value === '-' || value === '') return;
    
    // Navigate to events page with filter
    const params = new URLSearchParams();
    params.append(field, value);
    window.location.href = `/events/?${params.toString()}`;
}

/**
 * Run PQL Query from modal
 */
function runPQLQuery(query) {
    window.location.href = `/query/?q=${encodeURIComponent(query)}`;
}

/**
 * Utility Functions
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modals on escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeEventModal();
        closeAlertModal();
        closeAgentModal();
    }
});

// Close modals when clicking outside
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal-overlay')) {
        closeEventModal();
        closeAlertModal();
        closeAgentModal();
    }
});

