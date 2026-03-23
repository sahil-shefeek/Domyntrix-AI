const fs = require('fs');
const path = require('path');

// Read dashboard.js content
const dashboardContent = fs.readFileSync(path.resolve(__dirname, '../dashboard.js'), 'utf8');

// Function to extract a function's code from dashboard.js
function extractFunction(name) {
    const regex = new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\([\\s\\S]*?\\)\\s*{[\\s\\S]*?\\n}`, 'g');
    const match = dashboardContent.match(regex);
    if (!match) throw new Error(`Function ${name} not found in dashboard.js`);
    return match[0];
}

// Evaluate extracted functions in the same scope with shared state and stubs
eval(`
    var currentHistoryPage = 1;
    var totalHistoryPages = 1;
    var activeDrawerId = null;
    function loadHistory() {} // Stub for button click handlers
    
    ${extractFunction('renderHistoryTable')}
    ${extractFunction('renderDrawerContent')}
    ${extractFunction('toggleDrawer')}
    ${extractFunction('renderPagination')}
`);

// Mock Scan Data Fixtures
const MALICIOUS_SCAN = {
    id: 1, 
    domain: "chromnius.download", 
    malicious_status: 1,
    inference_time_ms: 232, 
    timestamp: "2024-01-15T10:00:00Z",
    features: { length: 18, n_ns: 2 },
    explanations: [{ 
        feature: "life_time", 
        label: "Domain Age",
        value: 365, 
        verdict: "Suspiciously young", 
        severity: "high" 
    }]
};

const BENIGN_WHITELISTED_SCAN = {
    id: 2, 
    domain: "google.com", 
    malicious_status: 0,
    inference_time_ms: 0, 
    timestamp: "2024-01-15T11:00:00Z",
    features: {}, 
    explanations: []
};

describe('extension/dashboard.js', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        // Setup minimal DOM fixture
        document.body.innerHTML = `
            <table id="history-table">
                <tbody id="history-table-body"></tbody>
            </table>
            <div id="history-pagination"></div>
            <div class="stats-grid">
                <div id="stat-total-scans"></div>
                <div id="stat-total-malicious"></div>
                <div id="stat-total-benign"></div>
                <div id="stat-avg-inference"></div>
                <div id="stat-whitelist-hits"></div>
            </div>
        `;
        // Reset shared state
        currentHistoryPage = 1;
        totalHistoryPages = 1;
        activeDrawerId = null;
    });

    describe('renderHistoryTable', () => {
        test('Renders correct number of rows (2 scans -> 4 tr elements)', () => {
            renderHistoryTable([MALICIOUS_SCAN, BENIGN_WHITELISTED_SCAN]);
            const tbody = document.getElementById('history-table-body');
            // 2 scans = 2 data rows + 2 drawer rows
            expect(tbody.querySelectorAll('tr').length).toBe(4);
        });

        test('Malicious badge rendered for malicious scan', () => {
            renderHistoryTable([MALICIOUS_SCAN]);
            const tbody = document.getElementById('history-table-body');
            expect(tbody.querySelector('.badge-malicious')).not.toBeNull();
            expect(tbody.querySelector('.badge-malicious').textContent).toBe('Malicious');
        });

        test('Benign badge rendered for benign scan', () => {
            renderHistoryTable([BENIGN_WHITELISTED_SCAN]);
            const tbody = document.getElementById('history-table-body');
            expect(tbody.querySelector('.badge-benign')).not.toBeNull();
            expect(tbody.querySelector('.badge-benign').textContent).toBe('Benign');
        });

        test('Whitelisted source badge for benign scan with empty features', () => {
            renderHistoryTable([BENIGN_WHITELISTED_SCAN]);
            const tbody = document.getElementById('history-table-body');
            expect(tbody.querySelector('.badge-whitelist')).not.toBeNull();
            expect(tbody.querySelector('.badge-whitelist').textContent).toContain('Whitelisted');
        });

        test('Model source badge for malicious scan with features', () => {
            renderHistoryTable([MALICIOUS_SCAN]);
            const tbody = document.getElementById('history-table-body');
            expect(tbody.querySelector('.badge-model')).not.toBeNull();
            expect(tbody.querySelector('.badge-model').textContent).toContain('Model');
        });

        test('Empty array results in empty table body message', () => {
            renderHistoryTable([]);
            const tbody = document.getElementById('history-table-body');
            expect(tbody.querySelectorAll('.history-row').length).toBe(0);
            expect(tbody.textContent).toContain('No scans found');
        });
    });

    describe('renderDrawerContent', () => {
        test('Whitelisted scan shows notice', () => {
            const html = renderDrawerContent(BENIGN_WHITELISTED_SCAN);
            expect(html).toContain("served from the trusted whitelist");
        });

        test('No explanations shows fallback', () => {
            const scan = { ...MALICIOUS_SCAN, explanations: [] };
            const html = renderDrawerContent(scan);
            expect(html).toContain("No XAI explanations available");
        });

        test('XAI cards rendered with correct data', () => {
            const html = renderDrawerContent(MALICIOUS_SCAN);
            expect(html).toContain('class="feature-grid"');
            expect(html).toContain("Suspiciously young");
            expect(html).toContain("Domain Age");
        });

        test('Severity class applied (high)', () => {
            const html = renderDrawerContent(MALICIOUS_SCAN);
            expect(html).toContain("feature-high");
        });
    });

    describe('toggleDrawer', () => {
        let row1, row2, drawer1, drawer2;

        beforeEach(() => {
            // Setup DOM for toggleDrawer
            document.getElementById('history-table-body').innerHTML = `
                <tr class="history-row" data-id="1" id="row-1"></tr>
                <tr class="drawer-row" id="drawer-1"></tr>
                <tr class="history-row" data-id="2" id="row-2"></tr>
                <tr class="drawer-row" id="drawer-2"></tr>
            `;
            row1 = document.getElementById('row-1');
            row2 = document.getElementById('row-2');
            drawer1 = document.getElementById('drawer-1');
            drawer2 = document.getElementById('drawer-2');
        });

        test('Opens drawer on first click', () => {
            toggleDrawer(MALICIOUS_SCAN, row1);
            expect(drawer1.classList.contains('open')).toBe(true);
            expect(row1.classList.contains('active')).toBe(true);
            expect(activeDrawerId).toBe(MALICIOUS_SCAN.id);
        });

        test('Closes drawer on second click', () => {
            toggleDrawer(MALICIOUS_SCAN, row1); // Open
            toggleDrawer(MALICIOUS_SCAN, row1); // Close
            expect(drawer1.classList.contains('open')).toBe(false);
            expect(row1.classList.contains('active')).toBe(false);
            expect(activeDrawerId).toBeNull();
        });

        test('Switches drawer (closes p1, opens p2)', () => {
            toggleDrawer(MALICIOUS_SCAN, row1); // Open 1
            toggleDrawer(BENIGN_WHITELISTED_SCAN, row2); // Switch to 2
            
            expect(drawer1.classList.contains('open')).toBe(false);
            expect(row1.classList.contains('active')).toBe(false);
            expect(drawer2.classList.contains('open')).toBe(true);
            expect(row2.classList.contains('active')).toBe(true);
            expect(activeDrawerId).toBe(BENIGN_WHITELISTED_SCAN.id);
        });
    });

    describe('renderPagination', () => {
        test('Renders Previous and Next buttons (page 2 of 5)', () => {
            currentHistoryPage = 2;
            totalHistoryPages = 5;
            renderPagination();
            
            const buttons = document.querySelectorAll('.pagination-btn');
            expect(buttons.length).toBe(2);
            expect(buttons[0].textContent).toContain('Previous');
            expect(buttons[1].textContent).toContain('Next');
            
            const info = document.querySelector('.page-info');
            expect(info.textContent).toBe('Page 2 of 5');
        });

        test('Previous disabled on first page', () => {
            currentHistoryPage = 1;
            totalHistoryPages = 5;
            renderPagination();
            
            const prevBtn = Array.from(document.querySelectorAll('.pagination-btn'))
                .find(b => b.textContent.includes('Previous'));
            expect(prevBtn.disabled).toBe(true);
        });

        test('Next disabled on last page', () => {
            currentHistoryPage = 5;
            totalHistoryPages = 5;
            renderPagination();
            
            const nextBtn = Array.from(document.querySelectorAll('.pagination-btn'))
                .find(b => b.textContent.includes('Next'));
            expect(nextBtn.disabled).toBe(true);
        });
    });
});
