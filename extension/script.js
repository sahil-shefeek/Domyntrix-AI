async function fetchData(current_url) {
	const revised_url = current_url.replaceAll("/", "_**_");
	
	try {
		const res = await fetch("http://127.0.0.1:5000/test_url/" + revised_url);
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
}, function(tabs) {
	const tabURL = tabs[0].url;
	fetchData(tabURL);
});
