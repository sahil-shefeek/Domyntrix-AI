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
    // For now, just a placeholder for initial data fetching
    console.log("Loading initial dashboard data...");
    await fetchScans(1); // Test fetch
}

function loadPanelData(panelKey) {
    console.log(`Switching to panel: ${panelKey}`);
    switch(panelKey) {
        case 'history':
            loadHistory();
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
 * Fetches paginated scan history from the backend.
 * @param {number} page - The page number to fetch.
 */
async function fetchScans(page = 1) {
    try {
        const baseUrl = await getBackendUrl();
        const response = await fetch(`${baseUrl}/scans?page=${page}&page_size=20`);
        if (!response.ok) throw new Error(`Backend error: ${response.status}`);
        
        const data = await response.json();
        console.log("Fetched scans:", data);
        return data;
    } catch (error) {
        console.error("Failed to fetch scans:", error);
        return null;
    }
}

// Panel stub functions - to be implemented in subsequent prompts
function loadHistory() { console.log("History panel loader called"); }
function loadMetrics() { console.log("Metrics panel loader called"); }
function loadFlaggedDomains() { console.log("Flagged domains panel loader called"); }
function loadTrustManager() { console.log("Trust manager panel loader called"); }
