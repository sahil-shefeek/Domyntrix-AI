const fs = require('fs');
const path = require('path');

// Read script.js content
const scriptContent = fs.readFileSync(path.resolve(__dirname, '../script.js'), 'utf8');

// Function to extract a function's code from script.js
function extractFunction(name) {
    const regex = new RegExp(`(?:async\\s+)?function\\s+${name}\\s*\\([\\s\\S]*?\\)\\s*{[\\s\\S]*?\\n}`, 'g');
    const match = scriptContent.match(regex);
    if (!match) throw new Error(`Function ${name} not found in script.js`);
    return match[0];
}

// Evaluate extracted functions in the test environment context
eval(extractFunction('getCachedResult'));
eval(extractFunction('setCachedResult'));
eval(extractFunction('showError'));

describe('extension/script.js', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        // Set up minimal DOM for showError
        document.body.innerHTML = `
            <div id="checking"><div class="status-card"></div></div>
            <div id="benign"><div class="status-card"></div></div>
            <div id="malicious"><div class="status-card"></div></div>
            <div id="error">
                <div class="status-card" style="display: none;"></div>
                <div class="status-message"></div>
            </div>
        `;
    });

    describe('getCachedResult', () => {
        test('Cache miss — key not present', async () => {
            chrome.storage.local.get.mockResolvedValue({});
            const result = await getCachedResult('example.com');
            expect(result).toBeNull();
            expect(chrome.storage.local.get).toHaveBeenCalledWith(['cache:example.com']);
        });

        test('Cache hit — valid unexpired entry', async () => {
            const entry = {
                result: { mal_status: 0 },
                expiresAt: Date.now() + 100000
            };
            chrome.storage.local.get.mockResolvedValue({ 'cache:example.com': entry });
            
            const result = await getCachedResult('example.com');
            expect(result).toEqual({ mal_status: 0 });
        });

        test('Cache hit — expired entry', async () => {
            const entry = {
                result: { mal_status: 0 },
                expiresAt: Date.now() - 1000
            };
            chrome.storage.local.get.mockResolvedValue({ 'cache:example.com': entry });
            
            const result = await getCachedResult('example.com');
            expect(result).toBeNull();
            expect(chrome.storage.local.remove).toHaveBeenCalledWith('cache:example.com');
        });
    });

    describe('setCachedResult', () => {
        test('Source is "model" — should cache', async () => {
            const result = { source: "model", mal_status: 0 };
            await setCachedResult('example.com', result);
            
            expect(chrome.storage.local.set).toHaveBeenCalledTimes(1);
            const callArgs = chrome.storage.local.set.mock.calls[0][0];
            const entry = callArgs['cache:example.com'];
            expect(entry.result).toEqual(result);
            // Check if expiresAt is approx 30 mins in the future
            const now = Date.now();
            expect(entry.expiresAt).toBeGreaterThanOrEqual(now + 29 * 60 * 1000);
            expect(entry.expiresAt).toBeLessThanOrEqual(now + 31 * 60 * 1000);
        });

        test('Source is "whitelist" — should NOT cache', async () => {
            const result = { source: "whitelist", mal_status: 0 };
            await setCachedResult('example.com', result);
            
            expect(chrome.storage.local.set).not.toHaveBeenCalled();
        });
    });

    describe('showError', () => {
        test('Error card becomes visible', () => {
            // Set checking visible to test hiding it
            document.querySelector("#checking .status-card").style.display = "block";
            
            showError("Backend offline");
            
            const errorCard = document.querySelector("#error .status-card");
            const errorMessage = document.querySelector("#error .status-message");
            const checkingCard = document.querySelector("#checking .status-card");
            
            expect(errorCard.style.display).toBe("block");
            expect(errorMessage.textContent).toBe("Backend offline");
            expect(checkingCard.style.display).toBe("none");
        });
    });
});
