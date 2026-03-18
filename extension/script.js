const BACKEND_TIMEOUT_MS = 5000;

async function getCachedResult(domain) {
	const key = "cache:" + domain;
	const storage = await chrome.storage.local.get([key]);
	const entry = storage[key];

	if (entry && Date.now() < entry.expiresAt) {
		return entry.result;
	} else if (entry) {
		await chrome.storage.local.remove(key);
	}
	return null;
}

async function setCachedResult(domain, result) {
	if (result.source === "model") {
		const key = "cache:" + domain;
		const entry = {
			result: result,
			expiresAt: Date.now() + (30 * 60 * 1000)
		};
		await chrome.storage.local.set({ [key]: entry });
	}
}

function showError(message) {
	const checkingCard = document.querySelector("#checking .status-card");
	if (checkingCard) checkingCard.style.display = "none";

	const benignCard = document.querySelector("#benign .status-card");
	if (benignCard) benignCard.style.display = "none";

	const maliciousCard = document.querySelector("#malicious .status-card");
	if (maliciousCard) maliciousCard.style.display = "none";

	const errorCard = document.querySelector("#error .status-card");
	if (errorCard) errorCard.style.display = "block";

	const errorMessage = document.querySelector("#error .status-message");
	if (errorMessage) errorMessage.textContent = message;
}

async function fetchData(current_url) {
	try {
		const storage = await chrome.storage.local.get(['apiBaseUrl', 'backendUrl', 'scanHistory']);
		let baseUrl = storage.backendUrl || storage.apiBaseUrl || "http://127.0.0.1:5000";
		baseUrl = baseUrl.replace(/\/$/, ''); // Normalization

		// Extract domain
		let domain = current_url;
		try {
			const urlObj = new URL(current_url);
			domain = urlObj.hostname.replace(/^www\./, '');
		} catch (e) {
			domain = current_url.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
		}

		let record;
		let fromCache = false;
		const cachedResult = await getCachedResult(domain);

		if (cachedResult) {
			record = cachedResult;
			fromCache = true;
		} else {
			const fetchPromise = fetch(`${baseUrl}/test_url`, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ url: current_url }),
			});

			const timeoutPromise = new Promise((_, reject) => {
				setTimeout(() => {
					reject(new Error("Timeout"));
				}, BACKEND_TIMEOUT_MS);
			});

			const res = await Promise.race([fetchPromise, timeoutPromise]);
			record = await res.json();

			await setCachedResult(domain, record);
		}

		// Save to scan history
		const newRecord = {
			url: current_url,
			status: record.mal_status,
			timestamp: new Date().toISOString(),
			features: record.features
		};

		let history = storage.scanHistory || [];
		// Keep a max of 50 records. Add new record to front.
		history.unshift(newRecord);
		if (history.length > 50) history = history.slice(0, 50);
		await chrome.storage.local.set({ scanHistory: history });

		// Hide checking state
		document.querySelector("#checking .status-card").style.display = "none";

		const features = record.features;
		const inferenceTime = record.inference_time_ms ? record.inference_time_ms.toFixed(2) + " ms" : "N/A";

		const setInferenceTime = (selector) => {
			const el = document.querySelector(selector);
			if (el) {
				el.textContent = `Inference Time: ${inferenceTime}`;
				if (fromCache) {
					const badge = document.createElement("span");
					badge.textContent = "⚡ Instant result";
					badge.style.background = "rgba(255,255,255,0.1)";
					badge.style.padding = "2px 6px";
					badge.style.borderRadius = "4px";
					badge.style.fontSize = "10px";
					badge.style.marginLeft = "6px";
					el.appendChild(badge);
				}
			}
		};

		function renderFeatures(containerId, record, startCollapsed) {
			const section = document.querySelector(`${containerId} .explainability-section`);
			const grid = document.querySelector(`${containerId} .feature-grid`);
			const header = document.querySelector(`${containerId} .explainability-header`);
			if (!section || !grid || !header) return;

			if (record.source === "whitelist" || !record.explanations || record.explanations.length === 0) {
				if (record.mal_status === 0) {
					section.style.display = "block";
					section.innerHTML = `<div style="font-size: 13px; color: #6ee7b7; padding: 12px; background: rgba(16, 185, 129, 0.1); border-radius: 8px; border: 1px solid rgba(16, 185, 129, 0.2); display: flex; align-items: center; gap: 8px;">
						<svg class="icon" style="width: 16px; height: 16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>
						This domain is on your trusted list.
					</div>`;
				} else {
					section.style.display = "none";
				}
				return;
			}

			grid.innerHTML = "";

			let hasHigh = false;
			let hasMedium = false;

			record.explanations.forEach(explanation => {
				if (explanation.severity === "high") hasHigh = true;
				if (explanation.severity === "medium") hasMedium = true;

				const item = document.createElement('div');
				item.className = `feature-item feature-${explanation.severity}`;

				item.innerHTML = `
					<span class="feature-label">${explanation.label}</span>
					<span class="feature-value">${explanation.value}</span>
					<span class="feature-verdict">${explanation.verdict}</span>
				`;
				grid.appendChild(item);
			});

			let headerText = "✓ No Risk Factors Detected";
			if (hasHigh) {
				headerText = "⚠ Risk Factors Detected";
			} else if (hasMedium) {
				headerText = "⚡ Some Caution Advised";
			}

			// Keep existing SVG icons, just replace the text node equivalent. 
			// Easiest is to rewrite the innerHTML of the header keeping the exact SVG paths from index.html
			header.innerHTML = `
				<svg class="icon" style="width: 14px; height: 14px; opacity: 0.8;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<circle cx="12" cy="12" r="10"></circle>
					<line x1="12" y1="16" x2="12" y2="12"></line>
					<line x1="12" y1="8" x2="12.01" y2="8"></line>
				</svg>
				${headerText}
				<svg class="icon chevron" style="width: 14px; height: 14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
					<polyline points="6 9 12 15 18 9"></polyline>
				</svg>
			`;

			if (grid.children.length > 0) {
				section.style.display = "block";
				if (startCollapsed) {
					section.classList.add('collapsed');
				} else {
					section.classList.remove('collapsed');
				}

				// Check if click handler exists to prevent duplicates
				if (!header.dataset.hasClick) {
					header.onclick = () => {
						section.classList.toggle('collapsed');
					};
					header.dataset.hasClick = "true";
				}
			} else {
				section.style.display = "none";
			}
		}

		if (record.mal_status == 1) {
			document.querySelector("#malicious .status-card").style.display = "block";
			document.querySelector("#benign .status-card").style.display = "none";

			const infTimeEl = document.querySelector("#malicious .inference-time");
			if (infTimeEl) setInferenceTime("#malicious .inference-time");

			renderFeatures("#malicious", record, false);

			const riskFactorsEl = document.querySelector("#malicious .risk-factors");
			if (riskFactorsEl) {
				riskFactorsEl.innerHTML = "";
				if (record.cached) {
					const li = document.createElement("li");
					li.textContent = "Verified recently via cache (features retrieved).";
					li.style.color = "rgba(255,255,255,0.7)";
					riskFactorsEl.appendChild(li);
				}

				if (features) {
					if (features?.life_time < 30 && features?.life_time >= 0) {
						const li = document.createElement("li");
						li.textContent = "Newly registered domain (high risk).";
						riskFactorsEl.appendChild(li);
					}
					if (features?.n_countries > 1) {
						const li = document.createElement("li");
						li.textContent = "Resolves to multiple geographic locations.";
						riskFactorsEl.appendChild(li);
					}
					if (features?.n_labels < 10) {
						const li = document.createElement("li");
						li.textContent = "Suspiciously low amount of web content.";
						riskFactorsEl.appendChild(li);
					}
				}
			}
		} else {
			document.querySelector("#benign .status-card").style.display = "block";
			document.querySelector("#malicious .status-card").style.display = "none";

			const infTimeEl = document.querySelector("#benign .inference-time");
			if (infTimeEl) setInferenceTime("#benign .inference-time");

			renderFeatures("#benign", record, true);
		}
	} catch (error) {
		let msg = "An unexpected error occurred. Please try again.";
		if (error.message === "Timeout") {
			msg = "The Domyntrix server took too long to respond. Is the backend running?";
		} else if (error.message.includes("Failed to fetch") || error.message.includes("NetworkError")) {
			msg = "Could not connect to the Domyntrix server. Please start the backend.";
		}
		showError(msg);
	}
}

chrome.tabs.query({
	active: true,
	lastFocusedWindow: true
}, function (tabs) {
	const tabURL = tabs[0].url;

	// Check for internal browser pages and other safe protocols
	if (
		!tabURL ||
		tabURL.startsWith("chrome://") ||
		tabURL.startsWith("edge://") ||
		tabURL.startsWith("about:") ||
		tabURL.startsWith("chrome-extension://") ||
		tabURL.startsWith("file://")
	) {
		// Hide checking state
		if (document.querySelector("#checking .status-card")) {
			document.querySelector("#checking .status-card").style.display = "none";
		}

		// Show safe/internal page status (reusing benign style as "safe")
		if (document.querySelector("#benign .status-card")) {
			document.querySelector("#benign .status-card").style.display = "block";
			document.querySelector("#benign .status-title").textContent = "Protected Page";
			document.querySelector("#benign .status-message").textContent = "This is a browser internal page and is safe by default.";
		}
		return;
	}

	fetchData(tabURL);
});

const settingsBtn = document.getElementById('openSettings');
if (settingsBtn) {
	settingsBtn.addEventListener('click', () => {
		if (chrome.runtime.openOptionsPage) {
			chrome.runtime.openOptionsPage();
		} else {
			window.open(chrome.runtime.getURL('options.html'));
		}
	});
}

const dashboardLink = document.getElementById('openDashboard');
if (dashboardLink) {
	dashboardLink.addEventListener('click', (e) => {
		e.preventDefault();
		chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
	});
}
