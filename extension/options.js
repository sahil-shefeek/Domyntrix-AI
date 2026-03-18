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
    const backendUrlInput = document.getElementById('backendUrl');
    const backendStatus = document.getElementById('backendStatus');
    const toast = document.getElementById('toast');

    async function loadSettings() {
        const storage = await chrome.storage.local.get(['apiBaseUrl', 'backendUrl']);
        let backendUrl = storage.backendUrl;

        // Migration logic
        if (!backendUrl && storage.apiBaseUrl) {
            backendUrl = storage.apiBaseUrl;
            await chrome.storage.local.set({ backendUrl });
            await chrome.storage.local.remove('apiBaseUrl');
        }

        backendUrlInput.value = backendUrl || 'http://127.0.0.1:5000';
    }

    // Debounced URL saving
    let debounceTimer;
    backendUrlInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(async () => {
            let value = backendUrlInput.value.trim();
            if (!value) {
                value = 'http://127.0.0.1:5000';
            }
            value = value.replace(/\/$/, '');
            await chrome.storage.local.set({ backendUrl: value });
            
            backendStatus.textContent = '✓ Saved successfully';
            backendStatus.className = 'status-msg success';
            setTimeout(() => { backendStatus.textContent = ''; }, 3000);
        }, 500);
    });

    // Domain Lists Fetching and Rendering
    async function fetchLists() {
        const storage = await chrome.storage.local.get(['backendUrl']);
        const baseUrl = storage.backendUrl || 'http://127.0.0.1:5000';

        try {
            const [wlRes, blRes] = await Promise.all([
                fetch(`${baseUrl}/whitelist`).catch(() => null),
                fetch(`${baseUrl}/blacklist`).catch(() => null)
            ]);

            if (wlRes && wlRes.ok) {
                const wlData = await wlRes.json();
                renderList(wlData.entries || [], document.getElementById('whitelistArea'), 'whitelist', baseUrl);
                document.getElementById('whitelistCount').textContent = (wlData.entries || []).length;
            }
            if (blRes && blRes.ok) {
                const blData = await blRes.json();
                renderList(blData.entries || [], document.getElementById('blacklistArea'), 'blacklist', baseUrl);
                document.getElementById('blacklistCount').textContent = (blData.entries || []).length;
            }
        } catch (error) {
            console.error('Failed to fetch lists:', error);
        }
    }

    function renderList(entries, containerEl, type, baseUrl) {
        containerEl.innerHTML = '';
        entries.forEach(entry => {
            const row = document.createElement('div');
            row.className = 'list-item';

            const details = document.createElement('div');
            details.className = 'item-details';

            const domainSpan = document.createElement('span');
            domainSpan.className = 'item-domain';
            domainSpan.textContent = entry.domain;

            const metaSpan = document.createElement('span');
            metaSpan.className = 'item-meta';
            const dateStr = new Date(entry.created_at).toLocaleString();
            metaSpan.textContent = entry.note ? `${entry.note} • ${dateStr}` : dateStr;

            details.appendChild(domainSpan);
            details.appendChild(metaSpan);

            const removeBtn = document.createElement('button');
            removeBtn.className = 'btn btn-danger';
            removeBtn.textContent = 'Remove';
            removeBtn.style.padding = '6px 12px';
            removeBtn.style.fontSize = '12px';

            removeBtn.addEventListener('click', async () => {
                removeBtn.disabled = true;
                try {
                    const res = await fetch(`${baseUrl}/${type}/${encodeURIComponent(entry.domain)}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        showPanelStatus(type, `✓ Removed ${entry.domain}`, 'success');
                        await fetchLists();
                    } else {
                        showPanelStatus(type, '✗ Failed to remove domain', 'error');
                        removeBtn.disabled = false;
                    }
                } catch (error) {
                    showPanelStatus(type, '✗ Network error', 'error');
                    removeBtn.disabled = false;
                }
            });

            row.appendChild(details);
            row.appendChild(removeBtn);
            containerEl.appendChild(row);
        });
    }

    function showPanelStatus(type, message, statusClass) {
        const el = document.getElementById(`${type}Status`);
        el.textContent = message;
        el.className = `status-msg ${statusClass}`;
        setTimeout(() => { el.textContent = ''; }, 3000);
    }

    async function handleAdd(type) {
        const domainInput = document.getElementById(`${type}Domain`);
        const noteInput = document.getElementById(`${type}Note`);
        const domain = domainInput.value.trim();
        const note = noteInput.value.trim();

        if (!domain) {
            showPanelStatus(type, '✗ Domain cannot be empty', 'error');
            return;
        }

        const storage = await chrome.storage.local.get(['backendUrl']);
        const baseUrl = storage.backendUrl || 'http://127.0.0.1:5000';

        try {
            const res = await fetch(`${baseUrl}/${type}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain, note: note || null })
            });

            if (res.status === 201 || res.status === 200) {
                showPanelStatus(type, '✓ Added successfully', 'success');
                domainInput.value = '';
                noteInput.value = '';
                await fetchLists();
            } else if (res.status === 409) {
                showPanelStatus(type, '✗ Domain already in list', 'error');
            } else if (res.status === 422) {
                showPanelStatus(type, '✗ Invalid domain format', 'error');
            } else {
                showPanelStatus(type, '✗ Failed to add domain', 'error');
            }
        } catch (error) {
            showPanelStatus(type, '✗ Could not reach backend', 'error');
        }
    }

    document.getElementById('addWhitelistBtn').addEventListener('click', () => handleAdd('whitelist'));
    document.getElementById('addBlacklistBtn').addEventListener('click', () => handleAdd('blacklist'));

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
    await fetchLists();
});
