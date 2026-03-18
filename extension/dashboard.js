// State Management
let currentHistoryPage = 1;
let totalHistoryPages = 1;
let allHistoryScans = []; // Current page's scans
let filteredScans = [];
let activeDrawerId = null;

// Metrics & Stats State
let cachedStats = null;
let trendChartInstance = null;
let metricsLoaded = false;
let flaggedLoaded = false;
let trustLoaded = false;
let backendUrl = "http://127.0.0.1:5000";

document.addEventListener('DOMContentLoaded', async () => {
    console.log("Domyntrix AI Dashboard initialized");

    const navItems = document.querySelectorAll('.nav-item');
    const panels = document.querySelectorAll('.panel');
    const loadingOverlay = document.getElementById('loading-overlay');

    // Tab switching logic
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetPanel = item.getAttribute('data-panel');
            
            // Update active nav item
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            // Update active panel
            panels.forEach(panel => {
                panel.classList.remove('active');
                if (panel.id === `panel-${targetPanel}`) {
                    panel.classList.add('active');
                    // Call panel-specific loader if defined
                    loadPanelData(targetPanel);
                }
            });
        });
    });

    // Initialize History Filters
    setupHistoryFilters();

    // Initialize Trust Manager Event Listeners
    setupTrustManager();

    // Handle loading overlay with minimum display time
    const minLoadingTime = 300;
    const startTime = Date.now();

    // Initial load
    await loadInitialData();

    const elapsedTime = Date.now() - startTime;
    const remainingTime = Math.max(0, minLoadingTime - elapsedTime);

    setTimeout(() => {
        if (loadingOverlay) {
            loadingOverlay.style.opacity = '0';
            setTimeout(() => {
                loadingOverlay.style.display = 'none';
            }, 400);
        }
    }, remainingTime);
});

async function getBackendUrl() {
    const storage = await chrome.storage.local.get(['backendUrl', 'apiBaseUrl']);
    let url = storage.backendUrl || storage.apiBaseUrl || "http://127.0.0.1:5000";
    return url.replace(/\/$/, '');
}

async function loadInitialData() {
    console.log("Loading initial dashboard data...");
    backendUrl = await getBackendUrl();
    await loadHistory(1);
}

function loadPanelData(panelKey) {
    console.log(`Switching to panel: ${panelKey}`);
    switch(panelKey) {
        case 'history':
            loadHistory(currentHistoryPage);
            break;
        case 'metrics':
            loadMetrics();
            break;
        case 'flagged':
            loadFlaggedDomains();
            break;
        case 'trust':
            loadTrustManager();
            break;
    }
}

/**
 * Fetches and renders the scan history.
 * @param {number} page - The page number to fetch.
 */
async function loadHistory(page = 1) {
    currentHistoryPage = page;
    const data = await fetchScans(page);
    
    if (data) {
        allHistoryScans = data.scans;
        totalHistoryPages = data.total_pages;
        applyFilters(); // This will also call renderHistoryTable
    } else {
        const tableBody = document.getElementById('history-table-body');
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px; color: var(--danger-color);">Failed to load history from backend.</td></tr>';
    }
}

async function fetchScans(page = 1) {
    try {
        const response = await fetch(`${backendUrl}/scans?page=${page}&page_size=20`);
        if (!response.ok) throw new Error(`Backend error: ${response.status}`);
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Failed to fetch scans:", error);
        return null;
    }
}

function setupHistoryFilters() {
    const searchInput = document.getElementById('domain-search');
    const verdictFilter = document.getElementById('verdict-filter');
    const clearBtn = document.getElementById('clear-filters');

    if (searchInput) {
        searchInput.addEventListener('input', () => applyFilters());
    }
    if (verdictFilter) {
        verdictFilter.addEventListener('change', () => applyFilters());
    }
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            searchInput.value = '';
            verdictFilter.value = 'all';
            applyFilters();
        });
    }
}

function applyFilters() {
    const searchQuery = document.getElementById('domain-search').value.toLowerCase();
    const verdictValue = document.getElementById('verdict-filter').value;

    filteredScans = allHistoryScans.filter(scan => {
        const matchesSearch = scan.domain.toLowerCase().includes(searchQuery);
        let matchesVerdict = true;
        if (verdictValue === 'benign') matchesVerdict = scan.malicious_status === 0;
        if (verdictValue === 'malicious') matchesVerdict = scan.malicious_status === 1;
        
        return matchesSearch && matchesVerdict;
    });

    renderHistoryTable(filteredScans);
    renderPagination();
}

function renderHistoryTable(scans) {
    const tableBody = document.getElementById('history-table-body');
    if (!tableBody) return;

    if (scans.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 40px; color: var(--text-dim);">No scans found matching your criteria.</td></tr>';
        return;
    }

    tableBody.innerHTML = '';
    scans.forEach(scan => {
        const isWhitelisted = !scan.features || Object.keys(scan.features).length === 0;
        const row = document.createElement('tr');
        row.className = 'history-row';
        row.dataset.id = scan.id;
        
        const verdictBadge = scan.malicious_status === 1 ? 
            '<span class="badge badge-malicious">Malicious</span>' : 
            '<span class="badge badge-benign">Benign</span>';
        
        const sourceBadge = isWhitelisted ?
            '<span class="badge badge-whitelist">⚡ Whitelisted</span>' :
            '<span class="badge badge-model">🧠 Model</span>';

        const inferenceTime = isWhitelisted ? '—' : `${Math.round(scan.inference_time_ms)}ms`;
        const timestamp = new Date(scan.timestamp).toLocaleString();

        row.innerHTML = `
            <td style="font-weight: 500; color: #fff;">${scan.domain}</td>
            <td>${verdictBadge}</td>
            <td>${inferenceTime}</td>
            <td>${timestamp}</td>
            <td>${sourceBadge}</td>
        `;

        row.addEventListener('click', () => toggleDrawer(scan, row));
        tableBody.appendChild(row);

        // Add hidden drawer row
        const drawerRow = document.createElement('tr');
        drawerRow.className = 'drawer-row';
        drawerRow.id = `drawer-${scan.id}`;
        drawerRow.innerHTML = `
            <td colspan="5" style="padding: 0;">
                <div class="drawer-content">
                    <div class="drawer-inner">
                        ${renderDrawerContent(scan)}
                    </div>
                </div>
            </td>
        `;
        tableBody.appendChild(drawerRow);
    });
}

function renderDrawerContent(scan) {
    const isWhitelisted = !scan.features || Object.keys(scan.features).length === 0;
    
    if (isWhitelisted) {
        return `<p class="whitelist-notice">This domain was served from the trusted whitelist — no model analysis was performed.</p>`;
    }

    if (!scan.explanations || scan.explanations.length === 0) {
        return `<p class="whitelist-notice">No XAI explanations available for this scan.</p>`;
    }

    const cards = scan.explanations.map(exp => `
        <div class="feature-item feature-${exp.severity || 'neutral'}">
            <div class="feature-label">${exp.feature || 'Unknown'}</div>
            <div class="feature-value">${exp.label || exp.value || 'N/A'}</div>
            <div class="feature-verdict">${exp.verdict || ''}</div>
        </div>
    `).join('');

    return `<div class="feature-grid">${cards}</div>`;
}

function toggleDrawer(scan, row) {
    const drawer = document.getElementById(`drawer-${scan.id}`);
    const isAlreadyOpen = drawer.classList.contains('open');

    // Close existing open drawer
    if (activeDrawerId && activeDrawerId !== scan.id) {
        const prevDrawer = document.getElementById(`drawer-${activeDrawerId}`);
        const prevRow = document.querySelector(`.history-row[data-id="${activeDrawerId}"]`);
        if (prevDrawer) prevDrawer.classList.remove('open');
        if (prevRow) prevRow.classList.remove('active');
    }

    if (isAlreadyOpen) {
        drawer.classList.remove('open');
        row.classList.remove('active');
        activeDrawerId = null;
    } else {
        drawer.classList.add('open');
        row.classList.add('active');
        activeDrawerId = scan.id;
    }
}

function renderPagination() {
    const container = document.getElementById('history-pagination');
    if (!container) return;

    container.innerHTML = '';
    
    // Page Info
    const info = document.createElement('div');
    info.className = 'page-info';
    info.textContent = `Page ${currentHistoryPage} of ${totalHistoryPages}`;
    
    // Previous Button
    const prevBtn = document.createElement('button');
    prevBtn.className = 'pagination-btn';
    prevBtn.disabled = currentHistoryPage === 1;
    prevBtn.innerHTML = `
        <svg style="width: 16px; height: 16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
        Previous
    `;
    prevBtn.addEventListener('click', () => loadHistory(currentHistoryPage - 1));

    // Next Button
    const nextBtn = document.createElement('button');
    nextBtn.className = 'pagination-btn';
    nextBtn.disabled = currentHistoryPage >= totalHistoryPages;
    nextBtn.innerHTML = `
        Next
        <svg style="width: 16px; height: 16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
    `;
    nextBtn.addEventListener('click', () => loadHistory(currentHistoryPage + 1));

    // Page Numbers (up to 5)
    const pagesContainer = document.createElement('div');
    pagesContainer.className = 'pagination-pages';
    
    let startPage = Math.max(1, currentHistoryPage - 2);
    let endPage = Math.min(totalHistoryPages, startPage + 4);
    
    if (endPage - startPage < 4) {
        startPage = Math.max(1, endPage - 4);
    }

    for (let i = startPage; i <= endPage; i++) {
        const pageNum = document.createElement('div');
        pageNum.className = `page-num ${i === currentHistoryPage ? 'active' : ''}`;
        pageNum.textContent = i;
        pageNum.addEventListener('click', () => loadHistory(i));
        pagesContainer.appendChild(pageNum);
    }

    container.appendChild(prevBtn);
    container.appendChild(pagesContainer);
    container.appendChild(nextBtn);
    container.appendChild(info);
}

// Panel stub functions - to be implemented in subsequent prompts
/**
 * Stats & Metrics Implementations
 */
async function fetchStats(force = false) {
    if (cachedStats && !force) return cachedStats;
    try {
        const response = await fetch(`${backendUrl}/stats`);
        if (!response.ok) throw new Error("Stats fetch failed");
        cachedStats = await response.json();
        return cachedStats;
    } catch (error) {
        console.error("Error fetching stats:", error);
        return null;
    }
}

async function loadMetrics(force = false) {
    if (metricsLoaded && !force) return;
    
    // Show loading state in cards if needed
    const stats = await fetchStats(force);
    if (!stats) return;

    // Populate KPI Cards
    document.getElementById('stat-total-scans').textContent = stats.total_scans;
    document.getElementById('stat-total-malicious').textContent = stats.total_malicious;
    document.getElementById('stat-total-benign').textContent = stats.total_benign;
    document.getElementById('stat-avg-inference').textContent = `${Math.round(stats.avg_inference_time_ms)} ms`;
    document.getElementById('stat-whitelist-hits').textContent = stats.whitelist_hits;

    renderTrendChart(stats.trend);
    metricsLoaded = true;
}

function renderTrendChart(trend) {
    const canvas = document.getElementById('trend-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    if (trendChartInstance) {
        trendChartInstance.destroy();
    }

    const labels = trend.map(t => {
        const d = new Date(t.date);
        return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    });
    
    const maliciousData = trend.map(t => t.malicious);
    const benignData = trend.map(t => t.benign);

    trendChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Malicious',
                    data: maliciousData,
                    backgroundColor: 'rgba(239, 68, 68, 0.8)',
                    borderRadius: 4,
                    stack: 'Stack 0'
                },
                {
                    label: 'Benign',
                    data: benignData,
                    backgroundColor: 'rgba(16, 185, 129, 0.8)',
                    borderRadius: 4,
                    stack: 'Stack 0'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    stacked: true,
                    grid: { display: false },
                    ticks: { color: 'rgba(255, 255, 255, 0.7)' }
                },
                y: {
                    stacked: true,
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { 
                        color: 'rgba(255, 255, 255, 0.7)',
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'end',
                    labels: { 
                        color: '#fff',
                        boxWidth: 12,
                        padding: 20
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            }
        }
    });
}

async function loadFlaggedDomains() {
    if (flaggedLoaded) return;
    
    const stats = await fetchStats();
    if (!stats) return;

    const listContainer = document.getElementById('flagged-list');
    if (!listContainer) return;

    if (!stats.top_flagged || stats.top_flagged.length === 0) {
        listContainer.innerHTML = `
            <div class="placeholder-card">
                <svg class="placeholder-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"></path><line x1="4" y1="22" x2="4" y2="15"></line></svg>
                <h2>No malicious domains detected yet.</h2>
                <p>Top threats will appear here as they are discovered.</p>
            </div>
        `;
        return;
    }

    const maxCount = stats.top_flagged[0].count;
    listContainer.innerHTML = stats.top_flagged.map((item, index) => {
        const width = (item.count / maxCount) * 100;
        return `
            <div class="flagged-item">
                <div class="flagged-bar-bg" style="width: ${width}%"></div>
                <div class="flagged-rank">${index + 1}</div>
                <div class="flagged-domain">${item.domain}</div>
                <div class="flagged-count">
                    <span class="count-badge">${item.count} detections</span>
                </div>
            </div>
        `;
    }).join('');
    
    flaggedLoaded = true;
}

/**
 * Trust Manager Implementation
 */
function setupTrustManager() {
    const addWhitelistBtn = document.getElementById('add-whitelist-btn');
    const addBlacklistBtn = document.getElementById('add-blacklist-btn');

    if (addWhitelistBtn) {
        addWhitelistBtn.addEventListener('click', () => handleAddTrust('whitelist'));
    }
    if (addBlacklistBtn) {
        addBlacklistBtn.addEventListener('click', () => handleAddTrust('blacklist'));
    }

    // Add enter key support for inputs
    ['whitelist', 'blacklist'].forEach(type => {
        const domainInput = document.getElementById(`${type}-domain-input`);
        const noteInput = document.getElementById(`${type}-note-input`);
        
        [domainInput, noteInput].forEach(input => {
            if (input) {
                input.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') handleAddTrust(type);
                });
            }
        });
    });
}

async function loadTrustManager() {
    if (trustLoaded) return;
    
    await Promise.all([
        fetchTrustList('whitelist'),
        fetchTrustList('blacklist')
    ]);
    
    trustLoaded = true;
}

async function fetchTrustList(type) {
    try {
        const response = await fetch(`${backendUrl}/${type}`);
        if (!response.ok) throw new Error(`${type} fetch failed`);
        
        const data = await response.json();
        const entries = data.entries || [];
        
        renderTrustList(entries, `${type}-list`, type);
        document.getElementById(`${type}-count`).textContent = entries.length;
    } catch (error) {
        console.error(`Error fetching ${type} list:`, error);
        const container = document.getElementById(`${type}-list`);
        if (container) {
            container.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.className = 'trust-empty';
            errDiv.style.color = 'var(--danger-color)';
            errDiv.textContent = `Failed to load ${type} list.`;
            container.appendChild(errDiv);
        }
    }
}

function renderTrustList(entries, containerId, type) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = '';

    if (entries.length === 0) {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'trust-empty';
        emptyDiv.textContent = `No ${type === 'whitelist' ? 'trusted' : 'blocked'} domains yet.`;
        container.appendChild(emptyDiv);
        return;
    }
    entries.forEach(entry => {
        const item = document.createElement('div');
        item.className = 'trust-item';

        const info = document.createElement('div');
        info.className = 'trust-item-info';

        const domainSpan = document.createElement('span');
        domainSpan.className = 'trust-item-domain';
        domainSpan.textContent = entry.domain;
        domainSpan.title = entry.domain;

        const metaSpan = document.createElement('span');
        metaSpan.className = 'trust-item-meta';
        const dateStr = new Date(entry.created_at).toLocaleString();
        metaSpan.textContent = entry.note ? `${entry.note} • ${dateStr}` : dateStr;

        info.appendChild(domainSpan);
        info.appendChild(metaSpan);

        const removeBtn = document.createElement('button');
        removeBtn.className = 'trust-remove-btn';
        removeBtn.textContent = 'Remove';
        removeBtn.addEventListener('click', () => handleRemoveTrust(type, entry.domain));

        item.appendChild(info);
        item.appendChild(removeBtn);
        container.appendChild(item);
    });
}

async function handleAddTrust(type) {
    const domainInput = document.getElementById(`${type}-domain-input`);
    const noteInput = document.getElementById(`${type}-note-input`);
    const statusEl = document.getElementById(`${type}-status`);
    const addBtn = document.getElementById(`add-${type}-btn`);

    const domain = domainInput.value.trim();
    const note = noteInput.value.trim();

    if (!domain) {
        showTrustStatus(statusEl, "✗ Domain cannot be empty", "error");
        return;
    }

    // Disable button and show loading logic
    addBtn.disabled = true;
    const originalText = addBtn.textContent;
    addBtn.textContent = 'Adding...';

    try {
        const response = await fetch(`${backendUrl}/${type}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, note: note || null })
        });

        if (response.status === 201 || response.status === 200) {
            showTrustStatus(statusEl, "✓ Added successfully", "success");
            domainInput.value = '';
            noteInput.value = '';
            
            // Immediate re-render
            await fetchTrustList(type);
            // Reset trustLoaded flag so navigating back re-fetches (just in case)
            trustLoaded = false; 
            // Also invalidate metrics cached stats if they exist
            metricsLoaded = false;
            flaggedLoaded = false;
        } else if (response.status === 409) {
            showTrustStatus(statusEl, "✗ Already in list", "error");
        } else if (response.status === 422) {
            showTrustStatus(statusEl, "✗ Invalid domain", "error");
        } else {
            showTrustStatus(statusEl, "✗ Failed to add", "error");
        }
    } catch (error) {
        console.error(`Error adding to ${type}:`, error);
        showTrustStatus(statusEl, "✗ Connection error", "error");
    } finally {
        addBtn.disabled = false;
        addBtn.textContent = originalText;
    }
}

async function handleRemoveTrust(type, domain) {
    if (!confirm(`Are you sure you want to remove ${domain} from ${type}?`)) return;

    try {
        const response = await fetch(`${backendUrl}/${type}/${encodeURIComponent(domain)}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            // Immediate re-render
            await fetchTrustList(type);
            // Reset flags
            trustLoaded = false;
            metricsLoaded = false;
            flaggedLoaded = false;
        } else {
            alert(`Failed to remove domain: ${response.status}`);
        }
    } catch (error) {
        console.error(`Error removing from ${type}:`, error);
        alert("Connection error while removing domain.");
    }
}

function showTrustStatus(el, message, className) {
    if (!el) return;
    el.textContent = message;
    el.className = `trust-status ${className}`;
    setTimeout(() => {
        if (el.textContent === message) {
            el.textContent = '';
            el.className = 'trust-status';
        }
    }, 3000);
}
