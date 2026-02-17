async function fetchData(current_url) {
	try {
		const res = await fetch("http://127.0.0.1:5000/test_url", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body: JSON.stringify({ url: current_url }),
		});
		const record = await res.json();

		// Hide checking state
		document.querySelector("#checking .status-card").style.display = "none";

		if (record.mal_status == 1) {
			document.querySelector("#malicious .status-card").style.display = "block";
			document.querySelector("#benign .status-card").style.display = "none";
		} else {
			document.querySelector("#benign .status-card").style.display = "block";
			document.querySelector("#malicious .status-card").style.display = "none";
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
