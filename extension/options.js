document.addEventListener('DOMContentLoaded', async () => {
    const tabs = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');

    // Tab switching logic
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            document.getElementById(tab.dataset.tab).classList.add('active');
        });
    });

    // History Logic
    const historyTableBody = document.getElementById('historyTableBody');
    const historyEmptyState = document.getElementById('historyEmptyState');
    const clearHistoryBtn = document.getElementById('clearHistoryBtn');

    async function loadHistory() {
        // Architecture Constraint 2: Async Storage Handling using Promise interface
        const { scanHistory } = await chrome.storage.local.get(['scanHistory']);

        // Clear current table
        historyTableBody.innerHTML = '';

        if (!scanHistory || scanHistory.length === 0) {
            historyEmptyState.style.display = 'block';
            historyTableBody.parentElement.style.display = 'none';
        } else {
            historyEmptyState.style.display = 'none';
            historyTableBody.parentElement.style.display = 'table';

            scanHistory.forEach(record => {
                const tr = document.createElement('tr');

                // Date Cell
                const dateTd = document.createElement('td');
                const dateObj = new Date(record.timestamp);
                dateTd.textContent = dateObj.toLocaleString();
                tr.appendChild(dateTd);

                // Domain Cell
                // Architecture Constraint 1: XSS PREVENTION via textContent
                const domainTd = document.createElement('td');
                domainTd.className = 'domain-cell';
                domainTd.textContent = record.url;
                domainTd.title = record.url;
                tr.appendChild(domainTd);

                // Status Cell
                const statusTd = document.createElement('td');
                const badge = document.createElement('span');
                badge.className = record.status === 1 ? 'badge malicious' : 'badge safe';
                badge.textContent = record.status === 1 ? 'Malicious' : 'Safe';
                statusTd.appendChild(badge);
                tr.appendChild(statusTd);

                historyTableBody.appendChild(tr);
            });
        }
    }

    clearHistoryBtn.addEventListener('click', async () => {
        if (confirm('Are you sure you want to clear your scan history?')) {
            await chrome.storage.local.remove('scanHistory');
            await loadHistory();
            showToast('History cleared');
        }
    });

    // Settings Logic
    const apiBaseUrlInput = document.getElementById('apiBaseUrl');
    const saveSettingsBtn = document.getElementById('saveSettingsBtn');
    const toast = document.getElementById('toast');

    async function loadSettings() {
        const { apiBaseUrl } = await chrome.storage.local.get(['apiBaseUrl']);
        if (apiBaseUrl) {
            apiBaseUrlInput.value = apiBaseUrl;
        } else {
            apiBaseUrlInput.value = 'http://127.0.0.1:5000';
        }
    }

    saveSettingsBtn.addEventListener('click', async () => {
        let value = apiBaseUrlInput.value.trim();
        if (!value) {
            value = 'http://127.0.0.1:5000';
        }

        // Architecture Constraint 3: URL Normalization to prevent // slash issues
        value = value.replace(/\/$/, '');

        await chrome.storage.local.set({ apiBaseUrl: value });
        showToast('Settings Saved');
    });

    function showToast(message) {
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }

    // Initial load
    await loadHistory();
    await loadSettings();
});
