// PSIRT Security Analysis Agent - Frontend JavaScript

const API_BASE = '/api';

// State
let currentTab = 'dashboard';
let analysisPolling = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

async function initializeApp() {
    // Check connection
    await checkHealth();

    // Setup navigation
    setupNavigation();

    // Setup file upload
    setupFileUpload();

    // Load initial data
    loadStatistics();
    loadAdvisories();
    loadInventory();
}

// Health Check
async function checkHealth() {
    const statusEl = document.getElementById('connection-status');
    try {
        const response = await fetch(`${API_BASE}/health`);
        const data = await response.json();

        if (data.status === 'healthy') {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status-badge status-connected';
        } else {
            statusEl.textContent = 'Degraded';
            statusEl.className = 'status-badge status-checking';
        }
    } catch (error) {
        statusEl.textContent = 'Disconnected';
        statusEl.className = 'status-badge status-disconnected';
    }
}

// Navigation
function setupNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            const tab = item.dataset.tab;
            switchTab(tab);
        });
    });
}

function switchTab(tab) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.tab === tab);
    });

    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `${tab}-tab`);
    });

    currentTab = tab;
}

// Statistics
async function loadStatistics() {
    try {
        const response = await fetch(`${API_BASE}/statistics`);
        const data = await response.json();

        const dist = data.severity_distribution || {};
        document.getElementById('critical-count').textContent = dist.Critical || 0;
        document.getElementById('high-count').textContent = dist.High || 0;
        document.getElementById('medium-count').textContent = dist.Medium || 0;
        document.getElementById('low-count').textContent = dist.Low || 0;
    } catch (error) {
        console.error('Failed to load statistics:', error);
    }
}

// Advisories
async function loadAdvisories() {
    const severity = document.getElementById('advisory-severity-filter')?.value || '';
    const bodyEl = document.getElementById('advisories-body');
    const recentEl = document.getElementById('recent-list');

    try {
        const params = new URLSearchParams({ limit: '50' });
        if (severity) params.append('severity', severity);

        const response = await fetch(`${API_BASE}/advisories?${params}`);
        const data = await response.json();

        if (data.advisories && data.advisories.length > 0) {
            // Render table
            bodyEl.innerHTML = data.advisories.map(adv => `
                <div class="table-row" onclick="showAdvisory('${adv.advisory_id}')">
                    <span>${adv.advisory_id}</span>
                    <span>${truncate(adv.title, 50)}</span>
                    <span><span class="severity-badge severity-${adv.severity.toLowerCase()}">${adv.severity}</span></span>
                    <span>${adv.risk_score.toFixed(1)}</span>
                    <span><button class="view-btn">View</button></span>
                </div>
            `).join('');

            // Render recent (top 5)
            recentEl.innerHTML = data.advisories.slice(0, 5).map(adv => `
                <div class="advisory-item" onclick="showAdvisory('${adv.advisory_id}')">
                    <div>
                        <div class="title">${truncate(adv.title, 40)}</div>
                        <div class="id">${adv.advisory_id}</div>
                    </div>
                    <span class="severity-badge severity-${adv.severity.toLowerCase()}">${adv.severity}</span>
                </div>
            `).join('');
        } else {
            bodyEl.innerHTML = '<p class="empty-message">No advisories found.</p>';
            recentEl.innerHTML = '<p class="empty-message">No advisories loaded. Run analysis to fetch PSIRT data.</p>';
        }
    } catch (error) {
        console.error('Failed to load advisories:', error);
        bodyEl.innerHTML = '<p class="empty-message">Failed to load advisories.</p>';
    }
}

async function showAdvisory(advisoryId) {
    const modal = document.getElementById('advisory-modal');
    const body = document.getElementById('modal-body');

    body.innerHTML = '<div class="loading"></div>';
    modal.classList.add('active');

    try {
        const response = await fetch(`${API_BASE}/advisories/${advisoryId}`);
        const adv = await response.json();

        body.innerHTML = `
            <h2>${adv.title}</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                <strong>${adv.advisory_id}</strong> |
                CVEs: ${adv.cve_ids?.join(', ') || 'N/A'}
            </p>

            <div style="display: flex; gap: 1rem; margin-bottom: 1.5rem;">
                <span class="severity-badge severity-${adv.severity.toLowerCase()}">${adv.severity}</span>
                <span style="color: var(--text-secondary);">Risk Score: ${adv.risk_score?.toFixed(1) || 'N/A'}/10</span>
                <span style="color: var(--text-secondary);">${adv.priority_level || ''}</span>
            </div>

            ${adv.when_is_this_a_problem ? `
                <h3 style="margin-top: 1.5rem;">When Is This A Problem?</h3>
                <p>${adv.when_is_this_a_problem}</p>
            ` : ''}

            ${adv.clear_conditions?.length ? `
                <h3 style="margin-top: 1.5rem;">Clear Conditions</h3>
                <ul>${adv.clear_conditions.map(c => `<li>${c}</li>`).join('')}</ul>
            ` : ''}

            ${adv.affected_products?.length ? `
                <h3 style="margin-top: 1.5rem;">Affected Products</h3>
                <ul>${adv.affected_products.map(p => `<li>${p}</li>`).join('')}</ul>
            ` : ''}

            ${adv.risk_assessment ? `
                <h3 style="margin-top: 1.5rem;">Risk Assessment</h3>
                <p><strong>Exploitability:</strong> ${adv.risk_assessment.exploitability}</p>
                <p><strong>CVSS Score:</strong> ${adv.risk_assessment.cvss_score || 'N/A'}</p>
                <p><strong>Impact:</strong> ${adv.risk_assessment.impact_description}</p>
            ` : ''}

            ${adv.mitigation ? `
                <h3 style="margin-top: 1.5rem;">Mitigation</h3>
                ${adv.mitigation.recommended_actions?.length ? `
                    <p><strong>Recommended Actions:</strong></p>
                    <ol>${adv.mitigation.recommended_actions.map(a => `<li>${a}</li>`).join('')}</ol>
                ` : ''}
                ${adv.mitigation.workarounds?.length ? `
                    <p><strong>Workarounds:</strong></p>
                    <ul>${adv.mitigation.workarounds.map(w => `<li>${w}</li>`).join('')}</ul>
                ` : ''}
                <p><strong>Upgrade Path:</strong> ${adv.mitigation.upgrade_path || 'N/A'}</p>
                <p><strong>Patches Available:</strong> ${adv.mitigation.patches_available ? 'Yes' : 'No'}</p>
            ` : ''}

            ${adv.affected_inventory?.length ? `
                <h3 style="margin-top: 1.5rem;">Affected Inventory</h3>
                <ul>${adv.affected_inventory.map(i => `<li>${i}</li>`).join('')}</ul>
            ` : ''}

            ${adv.url ? `
                <p style="margin-top: 1.5rem;">
                    <a href="${adv.url}" target="_blank" style="color: var(--primary);">View Original Advisory</a>
                </p>
            ` : ''}
        `;
    } catch (error) {
        body.innerHTML = `<p class="empty-message">Failed to load advisory details.</p>`;
    }
}

function closeModal() {
    document.getElementById('advisory-modal').classList.remove('active');
}

// Query
async function submitQuery() {
    const input = document.getElementById('query-input');
    const severity = document.getElementById('severity-filter').value;
    const resultsEl = document.getElementById('query-results');
    const btn = document.getElementById('query-btn');

    const question = input.value.trim();
    if (!question) return;

    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span> Thinking...';
    resultsEl.innerHTML = '<div style="text-align: center; padding: 2rem;"><span class="loading"></span></div>';

    try {
        const response = await fetch(`${API_BASE}/query`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                question,
                limit: 5,
                severity_filter: severity || null
            })
        });

        const data = await response.json();

        resultsEl.innerHTML = `
            <div class="result-answer">
                ${formatAnswer(data.answer)}
            </div>
            <div class="result-sources">
                <h4>Sources (Confidence: ${data.confidence})</h4>
                ${data.sources.map(s => `
                    <div class="source-item">
                        <span>${s.advisory_id} - ${truncate(s.title, 40)}</span>
                        <span class="severity-badge severity-${s.severity.toLowerCase()}">${s.severity}</span>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (error) {
        resultsEl.innerHTML = `<p class="empty-message">Error: ${error.message}</p>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <line x1="22" y1="2" x2="11" y2="13"/>
                <polygon points="22 2 15 22 11 13 2 9 22 2"/>
            </svg>
            Ask
        `;
    }
}

function formatAnswer(text) {
    // Convert markdown-like formatting
    return text
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code>$1</code>');
}

// File Upload
function setupFileUpload() {
    const zone = document.getElementById('upload-zone');
    const input = document.getElementById('file-input');

    zone.addEventListener('click', () => input.click());

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', () => {
        zone.classList.remove('dragover');
    });

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) uploadFile(file);
    });

    input.addEventListener('change', () => {
        if (input.files[0]) uploadFile(input.files[0]);
    });
}

async function uploadFile(file) {
    const zone = document.getElementById('upload-zone');
    zone.innerHTML = '<span class="loading"></span><p>Uploading...</p>';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_BASE}/upload`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        zone.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            <p>Uploaded ${data.total} devices successfully!</p>
        `;

        loadInventory();
    } catch (error) {
        zone.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
            </svg>
            <p>Upload failed: ${error.message}</p>
        `;
    }
}

async function loadInventory() {
    try {
        const response = await fetch(`${API_BASE}/inventory`);
        const data = await response.json();

        document.getElementById('device-count').textContent = `${data.total} devices`;
        document.getElementById('product-count').textContent = `${data.products?.length || 0} products`;

        const tableEl = document.getElementById('inventory-table');
        if (data.items && data.items.length > 0) {
            tableEl.innerHTML = `
                <div style="display: grid; grid-template-columns: 60px 1fr 1fr 1fr 1fr; gap: 1rem; padding: 0.75rem; background: var(--bg-tertiary); font-weight: 600; font-size: 0.875rem;">
                    <span>#</span>
                    <span>Layer</span>
                    <span>Node</span>
                    <span>Router</span>
                    <span>Version</span>
                </div>
                ${data.items.map(item => `
                    <div style="display: grid; grid-template-columns: 60px 1fr 1fr 1fr 1fr; gap: 1rem; padding: 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.875rem;">
                        <span>${item.serial_no}</span>
                        <span>${item.network_layer}</span>
                        <span>${item.node}</span>
                        <span>${item.router_type}</span>
                        <span>${item.current_version}</span>
                    </div>
                `).join('')}
            `;
        } else {
            tableEl.innerHTML = '<p class="empty-message">No inventory loaded.</p>';
        }
    } catch (error) {
        console.error('Failed to load inventory:', error);
    }
}

// Analysis
async function startAnalysis() {
    const btn = document.getElementById('start-analysis-btn');
    const progress = document.getElementById('analysis-progress');
    const productsInput = document.getElementById('products-input').value;

    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span> Starting...';
    progress.style.display = 'block';

    try {
        const products = productsInput ? productsInput.split(',').map(p => p.trim()) : null;

        await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                products,
                include_scraping: document.getElementById('include-scraping').checked
            })
        });

        // Start polling for status
        pollAnalysisStatus();
    } catch (error) {
        document.getElementById('progress-status').textContent = `Error: ${error.message}`;
        btn.disabled = false;
        btn.innerHTML = 'Start Analysis';
    }
}

function pollAnalysisStatus() {
    if (analysisPolling) clearInterval(analysisPolling);

    analysisPolling = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE}/status`);
            const data = await response.json();

            const fill = document.getElementById('progress-fill');
            const status = document.getElementById('progress-status');
            const messages = document.getElementById('progress-messages');
            const btn = document.getElementById('start-analysis-btn');

            status.textContent = `${data.status} - ${data.current_step}`;
            messages.innerHTML = data.messages.slice(-10).map(m => `<p>${m}</p>`).join('');

            // Estimate progress
            const steps = ['fetched', 'analyzed', 'risk_assessed', 'documented', 'completed'];
            const stepIndex = steps.indexOf(data.current_step);
            fill.style.width = `${((stepIndex + 1) / steps.length) * 100}%`;

            if (data.status === 'completed' || data.status === 'failed') {
                clearInterval(analysisPolling);
                btn.disabled = false;
                btn.innerHTML = `
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polygon points="5 3 19 12 5 21 5 3"/>
                    </svg>
                    Start Analysis
                `;

                // Reload data
                loadStatistics();
                loadAdvisories();
            }
        } catch (error) {
            console.error('Status poll error:', error);
        }
    }, 2000);
}

// Utilities
function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeModal();
    }

    if (e.key === 'Enter' && e.ctrlKey) {
        if (currentTab === 'query') {
            submitQuery();
        }
    }
});
