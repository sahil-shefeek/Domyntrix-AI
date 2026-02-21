async function fetchData(current_url) {
	try {
		const storage = await chrome.storage.local.get(['apiBaseUrl', 'scanHistory']);
		let baseUrl = storage.apiBaseUrl || "http://127.0.0.1:5000";
		baseUrl = baseUrl.replace(/\/$/, ''); // Normalization

		const res = await fetch(`${baseUrl}/test_url`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ url: current_url }),
		});
		const record = await res.json();

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

		function renderFeatures(containerId, featuresData, startCollapsed) {
			const section = document.querySelector(`${containerId} .explainability-section`);
			const grid = document.querySelector(`${containerId} .feature-grid`);
			const header = document.querySelector(`${containerId} .explainability-header`);
			if (!section || !grid || !featuresData || !header) return;

			grid.innerHTML = "";

			const featureConfig = [
				{ key: 'life_time', label: 'Domain Age', format: v => v < 0 ? 'Unknown' : v + ' days', isWarning: v => v >= 0 && v < 30 },
				{ key: 'entropy', label: 'Entropy', format: v => v.toFixed(2), isWarning: v => v > 4.5 },
				{ key: 'n_countries', label: 'Geo Locations', format: v => v, isWarning: v => v > 1 },
				{ key: 'n_ns', label: 'Name Servers', format: v => v, isWarning: v => v < 2 },
				{ key: 'length', label: 'Domain Length', format: v => v, isWarning: v => v > 20 },
				{ key: 'n_labels', label: 'URL Labels', format: v => v, isWarning: v => v < 10 }
			];

			featureConfig.forEach(config => {
				if (featuresData[config.key] !== undefined) {
					const value = featuresData[config.key];
					const warning = config.isWarning(value);

					const item = document.createElement('div');
					item.className = `feature-item ${warning ? 'warning' : ''}`;

					item.innerHTML = `
						<span class="feature-label">${config.label}</span>
						<span class="feature-value">${config.format(value)}</span>
					`;
					grid.appendChild(item);
				}
			});

			if (grid.children.length > 0) {
				section.style.display = "block";
				if (startCollapsed) {
					section.classList.add('collapsed');
				} else {
					section.classList.remove('collapsed');
				}

				// Optional: ensure handler is added only once
				header.onclick = () => {
					section.classList.toggle('collapsed');
				};
			} else {
				section.style.display = "none";
			}
		}

		if (record.mal_status == 1) {
			document.querySelector("#malicious .status-card").style.display = "block";
			document.querySelector("#benign .status-card").style.display = "none";

			const infTimeEl = document.querySelector("#malicious .inference-time");
			if (infTimeEl) infTimeEl.textContent = `Inference Time: ${inferenceTime}`;

			renderFeatures("#malicious", features, false);

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
			if (infTimeEl) infTimeEl.textContent = `Inference Time: ${inferenceTime}`;

			renderFeatures("#benign", features, true);
		}
	} catch (error) {
		// Show error state if API is not available
		document.querySelector("#checking .status-card").style.display = "none";
		document.querySelector("#checking .status-title").textContent = "Connection Error";
		document.querySelector("#checking .status-message").textContent = "Could not connect to the API server. Make sure it is running on localhost:5000";
		document.querySelector("#checking .status-card").style.display = "block";
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
