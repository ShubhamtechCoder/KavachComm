// Configuration
const BASE_PIN = "2024"; // Your specified base PIN
const PIN_REFRESH_SECONDS = 30;
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const EMERGENCY_CONTACTS = [
  { name: "Security Team", number: "+1-555-123-4567" },
  { name: "IT Support", number: "+1-555-987-6543" },
  { name: "Law Enforcement", number: "+1-555-911-9111" },
  { name: "Management", number: "+1-555-000-0001" }
];

// DOM Elements
const pinContainer = document.getElementById('pin-container');
const appContainer = document.getElementById('app-container');
const pinInput = document.getElementById('pin-input');
const pinSubmit = document.getElementById('pin-submit');
const pinError = document.getElementById('pin-error');
const countdownEl = document.getElementById('pin-countdown');
const timerBar = document.getElementById('timer-bar');
const lastAuth = document.getElementById('last-auth');
const themeToggle = document.getElementById('theme-toggle');
const logoutBtn = document.getElementById('logout-btn');
const emergencyBtn = document.getElementById('emergency-btn');
const emergencyModal = document.getElementById('emergency-modal');
const lockSystemBtn = document.getElementById('lock-system-btn');
const wipeDataBtn = document.getElementById('wipe-data-btn');
const fakeScreenBtn = document.getElementById('fake-screen-btn');
const wipeKeysBtn = document.getElementById('wipe-keys-btn');
const closeModal = document.querySelectorAll('.close-modal');
const plaintext = document.getElementById('plaintext');
const ciphertext = document.getElementById('ciphertext');
const encryptedText = document.getElementById('encrypted-text');
const decryptedText = document.getElementById('decrypted-text');
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const clearEncrypt = document.getElementById('clear-encrypt');
const clearDecrypt = document.getElementById('clear-decrypt');
const selfDestructBtn = document.getElementById('self-destruct-btn');
const burnAfterCheckbox = document.getElementById('burn-after');
const ttlInput = document.getElementById('ttl');
const messageHistory = document.getElementById('message-history');
const clearHistoryBtn = document.getElementById('clear-history');
const threatLevel = document.getElementById('threat-level');
const threatStatus = document.getElementById('threat-status');
const threatLevelText = document.getElementById('threat-level-text');
const messageModal = document.getElementById('message-modal');
const messageDetailsContent = document.getElementById('message-details-content');
const privacyLink = document.getElementById('privacy-link');
const termsLink = document.getElementById('terms-link');
const contactLink = document.getElementById('contact-link');
const keyVaultBtn = document.getElementById('key-vault-btn');
const keyVaultModal = document.getElementById('key-vault-modal');
const keyVaultStatus = document.getElementById('key-vault-status');
const keysListMini = document.getElementById('keys-list-mini');
const fileModal = document.getElementById('file-modal');
const fileEncryptionBtn = document.getElementById('file-encryption-btn');
const encryptFileBtn = document.getElementById('encrypt-file-btn');
const decryptFileBtn = document.getElementById('decrypt-file-btn');
const emergencyContactsList = document.getElementById('emergency-contacts-list');

// State
let messages = JSON.parse(localStorage.getItem('messageHistory')) || [];
let keyVault = JSON.parse(localStorage.getItem('keyVault')) || [];
let threatLevelValue = 10;
let selfDestructTimers = {};
let pinRefreshTimer;
let emergencyProtocolActive = false;
let failedAttempts = 0;
let lastAttemptTime = 0;
let currentEncryptionKey = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Theme
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
        themeToggle.checked = true;
    }
    
    // Start PIN refresh countdown
    startPinRefreshCountdown();
    
    // Load message history
    renderMessageHistory();
    
    // Initialize threat monitoring
    startThreatMonitoring();
    
    // Set up event listeners
    setupEventListeners();
    
    // Initialize key vault
    renderKeyVault();
    renderMiniKeyList();
    
    // Render emergency contacts
    renderEmergencyContacts();
    
    // Demo hint
    console.log("Current PIN:", generateCurrentPin());
});

// Time-based PIN Generator
function generateCurrentPin() {
    const now = new Date();
    const currentMinute = now.getMinutes().toString().padStart(2, '0');
    return BASE_PIN + currentMinute;
}

// Countdown Timer
function startPinRefreshCountdown() {
    clearInterval(pinRefreshTimer);
    
    const updateCountdown = () => {
        const now = new Date();
        const secondsLeft = PIN_REFRESH_SECONDS - (now.getSeconds() % PIN_REFRESH_SECONDS);
        
        countdownEl.textContent = secondsLeft;
        timerBar.style.width = `${(secondsLeft / PIN_REFRESH_SECONDS) * 100}%`;
        
        if (secondsLeft <= 5) {
            countdownEl.style.color = "var(--drdo-error)";
            countdownEl.classList.add('alert-pulse');
        } else {
            countdownEl.style.color = "var(--drdo-accent)";
            countdownEl.classList.remove('alert-pulse');
        }
        
        if (secondsLeft === PIN_REFRESH_SECONDS) {
            pinInput.placeholder = "Enter new PIN";
            pinInput.value = "";
            pinInput.focus();
        }
    };
    
    updateCountdown();
    pinRefreshTimer = setInterval(updateCountdown, 1000);
}

// Authentication
function authenticate() {
    if (emergencyProtocolActive) {
        showEmergencyLockdown();
        return;
    }

    const now = Date.now();
    if (now - lastAttemptTime < 2000) {
        pinError.textContent = "Too many attempts. Wait 2 seconds.";
        return;
    }
    lastAttemptTime = now;

    const enteredPin = pinInput.value.trim();
    const currentPin = generateCurrentPin();
    
    const currentTime = new Date();
    const previousMinute = currentTime.getMinutes() - (currentTime.getSeconds() < PIN_REFRESH_SECONDS ? 0 : 1);
    const previousPin = BASE_PIN + (previousMinute < 0 ? 59 : previousMinute).toString().padStart(2, '0');
    
    if (enteredPin === currentPin || enteredPin === previousPin) {
        pinError.textContent = "";
        pinContainer.style.display = "none";
        appContainer.style.display = "block";
        lastAuth.textContent = new Date().toLocaleString();
        appContainer.classList.add('fade-in');
        
        threatLevelValue = Math.max(threatLevelValue - 30, 10);
        updateThreatDisplay();
        
        addToMessageHistory({
            type: 'system',
            content: 'User authenticated successfully',
            timestamp: new Date().toISOString()
        });
        
        failedAttempts = 0;
    } else {
        failedAttempts++;
        pinError.textContent = `Invalid PIN. Current time: ${currentTime.getHours()}:${currentTime.getMinutes().toString().padStart(2, '0')}`;
        pinInput.value = "";
        pinInput.focus();
        pinError.classList.add('shake');
        setTimeout(() => pinError.classList.remove('shake'), 500);
        
        threatLevelValue = Math.min(threatLevelValue + 20, 100);
        updateThreatDisplay();
        
        addToMessageHistory({
            type: 'system',
            content: 'Failed authentication attempt',
            timestamp: new Date().toISOString()
        });
        
        if (failedAttempts >= 3) {
            setTimeout(() => {
                lockSystem();
                pinError.textContent = "System locked due to multiple failed attempts";
            }, 1000);
        }
    }
}

// Encryption/Decryption
function simulateEncryption(text) {
    return btoa(unescape(encodeURIComponent(text)));
}

function simulateDecryption(text) {
    try {
        return decodeURIComponent(escape(atob(text)));
    } catch {
        return "ERROR: Invalid encrypted message";
    }
}

function encryptMessage() {
    if (emergencyProtocolActive) {
        showEmergencyLockdown();
        return;
    }

    if (!plaintext.value.trim()) {
        alert("Please enter a message to encrypt");
        return;
    }
    
    const encrypted = simulateEncryption(plaintext.value);
    ciphertext.value = encrypted;
    
    const messageObj = {
        type: 'encrypted',
        content: plaintext.value,
        encrypted: encrypted,
        timestamp: new Date().toISOString(),
        burnAfter: burnAfterCheckbox.checked,
        ttl: ttlInput.value ? parseInt(ttlInput.value) : null
    };
    
    addToMessageHistory(messageObj);
    
    if (burnAfterCheckbox.checked || ttlInput.value) {
        setSelfDestruct(messageObj);
    }
}

function decryptMessage() {
    if (emergencyProtocolActive) {
        showEmergencyLockdown();
        return;
    }

    if (!encryptedText.value.trim()) {
        alert("Please enter an encrypted message");
        return;
    }
    
    const decrypted = simulateDecryption(encryptedText.value);
    decryptedText.value = decrypted;
    
    addToMessageHistory({
        type: 'decrypted',
        content: decrypted,
        encrypted: encryptedText.value,
        timestamp: new Date().toISOString()
    });
    
    const message = messages.find(m => m.encrypted === encryptedText.value);
    if (message && message.burnAfter) {
        setTimeout(() => {
            encryptedText.value = "";
            decryptedText.value = "";
            document.getElementById('message-warning').textContent = "Message has been destroyed";
            document.getElementById('message-warning').style.display = "block";
        }, 5000);
    }
}

// File Encryption/Decryption
async function handleFileEncryption() {
    const fileInput = document.getElementById('file-to-encrypt');
    const statusElement = document.getElementById('file-encryption-status');
    const progressContainer = document.querySelector('#file-modal .file-upload-box .progress-container');
    const progressBar = document.getElementById('encrypt-progress');
    const progressStatus = document.getElementById('encrypt-status');
    const key = document.getElementById('security-key').textContent;

    if (!fileInput.files || fileInput.files.length === 0) {
        showFileStatus(statusElement, "Please select a file first", "error");
        return;
    }

    if (!key) {
        showFileStatus(statusElement, "Please generate a security key first", "error");
        return;
    }

    const file = fileInput.files[0];
    if (file.size > MAX_FILE_SIZE) {
        showFileStatus(statusElement, `File too large (max ${MAX_FILE_SIZE/1024/1024}MB)`, "error");
        return;
    }

    progressContainer.classList.remove('hidden');
    progressBar.value = 0;
    progressStatus.textContent = '0%';
    showFileStatus(statusElement, "Starting encryption...", "processing");

    try {
        const derivedKey = await deriveKeyFromString(key);
        const encrypted = await encryptFileWithKey(file, derivedKey, (progress) => {
            progressBar.value = progress;
            progressStatus.textContent = `${progress}%`;
        });

        const encryptedFileName = `${file.name}.kcenc`;
        downloadFile(encrypted, encryptedFileName);
        
        const keyObj = keyVault.find(k => k.key === key);
        if (keyObj) {
            keyObj.fileName = file.name;
            keyObj.encryptedFileName = encryptedFileName;
            keyObj.timestamp = new Date().toISOString();
            localStorage.setItem('keyVault', JSON.stringify(keyVault));
            renderMiniKeyList();
        }

        showFileStatus(statusElement, "File encrypted successfully!", "success");
        addToMessageHistory({
            type: 'system',
            content: `Encrypted file: ${file.name} with key ${key.slice(0, 8)}...`,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error("Encryption error:", error);
        showFileStatus(statusElement, `Encryption failed: ${error.message}`, "error");
    } finally {
        setTimeout(() => {
            progressContainer.classList.add('hidden');
        }, 2000);
    }
}

async function handleFileDecryption() {
    const fileInput = document.getElementById('file-to-decrypt');
    const statusElement = document.getElementById('file-decryption-status');
    const progressContainer = document.querySelectorAll('#file-modal .file-upload-box .progress-container')[1];
    const progressBar = document.getElementById('decrypt-progress');
    const progressStatus = document.getElementById('decrypt-status');
    const key = document.getElementById('decryption-key').value.trim();

    if (!fileInput.files || fileInput.files.length === 0) {
        showFileStatus(statusElement, "Please select a file first", "error");
        return;
    }

    if (!key) {
        showFileStatus(statusElement, "Please enter the security key", "error");
        return;
    }

    const file = fileInput.files[0];
    if (!file.name.endsWith('.kcenc')) {
        showFileStatus(statusElement, "Only .kcenc files can be decrypted", "error");
        return;
    }

    progressContainer.classList.remove('hidden');
    progressBar.value = 0;
    progressStatus.textContent = '0%';
    showFileStatus(statusElement, "Starting decryption...", "processing");

    try {
        const derivedKey = await deriveKeyFromString(key);
        const decrypted = await decryptFileWithKey(file, derivedKey, (progress) => {
            progressBar.value = progress;
            progressStatus.textContent = `${progress}%`;
        });

        let fileName = file.name;
        if (fileName.endsWith('.kcenc')) {
            fileName = fileName.slice(0, -6);
        }

        downloadFile(decrypted, fileName);
        
        const keyObj = keyVault.find(k => k.key === key);
        if (keyObj) {
            keyObj.used = true;
            keyObj.lastUsed = new Date().toISOString();
            localStorage.setItem('keyVault', JSON.stringify(keyVault));
            renderKeyVault();
            renderMiniKeyList();
        }

        showFileStatus(statusElement, "File decrypted successfully!", "success");
        addToMessageHistory({
            type: 'system',
            content: `Decrypted file: ${file.name} with key ${key.slice(0, 8)}...`,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error("Decryption error:", error);
        showFileStatus(statusElement, `Decryption failed: ${error.message.replace("Decryption failed: ", "")}`, "error");
    } finally {
        setTimeout(() => {
            progressContainer.classList.add('hidden');
        }, 2000);
    }
}

// Key derivation function
async function deriveKeyFromString(password) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const salt = encoder.encode("KavachCommStaticSalt");
    
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// Enhanced encryption with derived key
async function encryptFileWithKey(file, key, progressCallback) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = async (e) => {
            try {
                const arrayBuffer = e.target.result;
                const iv = crypto.getRandomValues(new Uint8Array(12));
                
                progressCallback(10);
                const encrypted = await crypto.subtle.encrypt(
                    { name: "AES-GCM", iv },
                    key,
                    arrayBuffer
                );
                
                progressCallback(90);
                const metadata = {
                    version: "2.0",
                    originalName: file.name,
                    timestamp: new Date().toISOString(),
                    system: "KavachComm"
                };
                
                // Ensure clean JSON formatting
                const metadataStr = JSON.stringify(metadata);
                const metadataBuffer = new TextEncoder().encode(metadataStr);
                const metadataLength = new Uint16Array([metadataBuffer.byteLength]);
                
                // Create output buffer with proper structure
                const result = new Uint8Array(
                    iv.length + metadataLength.byteLength + metadataBuffer.length + encrypted.byteLength
                );
                
                result.set(iv, 0);
                result.set(new Uint8Array(metadataLength.buffer), iv.length);
                result.set(metadataBuffer, iv.length + metadataLength.byteLength);
                result.set(new Uint8Array(encrypted), iv.length + metadataLength.byteLength + metadataBuffer.length);
                
                progressCallback(100);
                resolve(result.buffer);
            } catch (error) {
                reject(error);
            }
        };
        
        reader.onerror = () => reject(new Error("File reading failed"));
        reader.readAsArrayBuffer(file);
    });
}
// Fixed decryption function
async function decryptFileWithKey(file, key, progressCallback) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = async (e) => {
            const arrayBuffer = e.target.result;
            try {
                // 1. Extract fixed-length header (12-byte IV + 2-byte metadata length)
                const headerView = new DataView(arrayBuffer, 0, 14);
                const iv = new Uint8Array(arrayBuffer, 0, 12);
                const metadataLength = headerView.getUint16(12, true); // little-endian
                
                // 2. Extract metadata
                const metadataStart = 14;
                const metadataEnd = metadataStart + metadataLength;
                const metadataBuffer = new Uint8Array(arrayBuffer, metadataStart, metadataLength);
                
                // Clean the metadata string - remove any non-printable characters
                let metadataStr = new TextDecoder('utf-8', { fatal: false }).decode(metadataBuffer);
                
                // Find the first complete JSON object in the metadata
                const jsonStart = metadataStr.indexOf('{');
                const jsonEnd = metadataStr.lastIndexOf('}') + 1;
                
                if (jsonStart === -1 || jsonEnd <= jsonStart) {
                    throw new Error("Invalid metadata format - no valid JSON found");
                }
                
                metadataStr = metadataStr.substring(jsonStart, jsonEnd);
                
                // Parse the cleaned JSON
                const metadata = JSON.parse(metadataStr);
                
                // 3. Validate metadata version
                if (metadata.version !== "2.0") {
                    throw new Error(`Incompatible file version (expected 2.0, got ${metadata.version || 'none'})`);
                }
                
                // 4. Extract encrypted data
                const encryptedData = new Uint8Array(arrayBuffer, metadataEnd);
                
                progressCallback(30);
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv },
                    key,
                    encryptedData
                );
                
                progressCallback(100);
                resolve(decrypted);
                
            } catch (error) {
                console.error("Detailed Decryption Error:", {
                    error: error.message,
                    fileSize: file.size,
                    fileName: file.name,
                    stack: error.stack
                });
                reject(new Error(`Decryption failed: ${error.message.replace("Decryption failed: ", "")}`));
            }
        };
        
        reader.onerror = () => reject(new Error("Failed to read file"));
        reader.readAsArrayBuffer(file);
    });
}

function downloadFile(data, filename) {
    const blob = new Blob([data]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function showFileStatus(element, message, type) {
    element.textContent = message;
    element.style.display = "block";
    element.style.backgroundColor = type === "error" ? "var(--drdo-error)" : 
                                  type === "success" ? "var(--drdo-success)" : "var(--drdo-blue)";
    element.style.color = "white";
    element.style.padding = "0.5rem";
    element.style.borderRadius = "4px";
}

// Key Management
function generateNewKey() {
    const keyArray = new Uint32Array(8);
    crypto.getRandomValues(keyArray);
    currentEncryptionKey = Array.from(keyArray)
        .map(b => b.toString(16).padStart(8, '0'))
        .join('-');
    
    document.getElementById('security-key').textContent = currentEncryptionKey;
    document.getElementById('key-display').classList.remove('hidden');
    addToKeyVault(currentEncryptionKey);
}

function addToKeyVault(key) {
    const keyObj = {
        id: crypto.randomUUID(),
        key: key,
        timestamp: new Date().toISOString(),
        used: false
    };
    
    keyVault.unshift(keyObj);
    localStorage.setItem('keyVault', JSON.stringify(keyVault));
    renderKeyVault();
    renderMiniKeyList();
    updateKeyVaultStatus();
}

function renderKeyVault() {
    const keysList = document.getElementById('keys-list');
    keysList.innerHTML = '';
    
    if (keyVault.length === 0) {
        keysList.innerHTML = '<p class="no-keys">No keys in vault</p>';
        return;
    }
    
    keyVault.forEach(keyObj => {
        const keyItem = document.createElement('div');
        keyItem.className = 'key-item';
        keyItem.innerHTML = `
            <div class="key-info">
                <div class="key-time">${new Date(keyObj.timestamp).toLocaleString()}</div>
                <div class="key-value">${keyObj.key}</div>
                ${keyObj.fileName ? `<div class="key-file">File: ${keyObj.fileName}</div>` : ''}
                ${keyObj.used ? `<div class="key-used"><i class="fas fa-check-circle"></i> Used</div>` : ''}
            </div>
            <div class="key-actions">
                <button class="btn btn-small use-key-btn" data-id="${keyObj.id}">
                    <i class="fas fa-key"></i> Use
                </button>
                <button class="btn btn-small delete-key-btn" data-id="${keyObj.id}">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
        keysList.appendChild(keyItem);
    });
    
    document.querySelectorAll('.use-key-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const keyId = e.target.closest('button').dataset.id;
            useKeyFromVault(keyId);
        });
    });
    
    document.querySelectorAll('.delete-key-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const keyId = e.target.closest('button').dataset.id;
            deleteKeyFromVault(keyId);
        });
    });
}

function renderMiniKeyList() {
    keysListMini.innerHTML = '';
    
    const recentKeys = keyVault.slice(0, 3);
    if (recentKeys.length === 0) {
        keysListMini.innerHTML = '<p class="no-keys">No keys generated yet</p>';
        return;
    }
    
    recentKeys.forEach(keyObj => {
        const keyItem = document.createElement('div');
        keyItem.className = 'key-item-mini';
        keyItem.innerHTML = `
            <div>${keyObj.key.slice(0, 8)}...${keyObj.key.slice(-4)}</div>
            <div class="key-time-mini">${new Date(keyObj.timestamp).toLocaleTimeString()}</div>
        `;
        keysListMini.appendChild(keyItem);
    });
}

function updateKeyVaultStatus() {
    keyVaultStatus.textContent = `${keyVault.length} key${keyVault.length !== 1 ? 's' : ''} in vault`;
}

function useKeyFromVault(keyId) {
    const keyObj = keyVault.find(k => k.id === keyId);
    if (keyObj) {
        document.getElementById('decryption-key').value = keyObj.key;
        keyObj.used = true;
        localStorage.setItem('keyVault', JSON.stringify(keyVault));
        renderKeyVault();
        renderMiniKeyList();
    }
}

function deleteKeyFromVault(keyId) {
    if (confirm("Are you sure you want to delete this key? You won't be able to decrypt files using this key.")) {
        keyVault = keyVault.filter(k => k.id !== keyId);
        localStorage.setItem('keyVault', JSON.stringify(keyVault));
        renderKeyVault();
        renderMiniKeyList();
        updateKeyVaultStatus();
    }
}

function exportKeys() {
    const data = JSON.stringify(keyVault, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kavachcomm-keys-${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function importKeys() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    
    input.onchange = e => {
        const file = e.target.files[0];
        const reader = new FileReader();
        
        reader.onload = event => {
            try {
                const importedKeys = JSON.parse(event.target.result);
                if (Array.isArray(importedKeys)) {
                    keyVault = [...importedKeys, ...keyVault];
                    localStorage.setItem('keyVault', JSON.stringify(keyVault));
                    renderKeyVault();
                    renderMiniKeyList();
                    updateKeyVaultStatus();
                    alert(`Successfully imported ${importedKeys.length} keys`);
                } else {
                    throw new Error("Invalid key file format");
                }
            } catch (error) {
                alert("Error importing keys: " + error.message);
            }
        };
        
        reader.readAsText(file);
    };
    
    input.click();
}

function wipeKeyVault() {
    if (confirm("WARNING: This will permanently delete all encryption keys. You won't be able to decrypt any files without these keys. Continue?")) {
        keyVault = [];
        localStorage.removeItem('keyVault');
        renderKeyVault();
        renderMiniKeyList();
        updateKeyVaultStatus();
        alert("All encryption keys have been securely wiped");
    }
}

// Message History
function addToMessageHistory(message) {
    messages.unshift(message);
    if (messages.length > 100) {
        messages = messages.slice(0, 100);
    }
    localStorage.setItem('messageHistory', JSON.stringify(messages));
    renderMessageHistory();
}

function renderMessageHistory() {
    messageHistory.innerHTML = "";
    
    if (messages.length === 0) {
        messageHistory.innerHTML = '<p class="no-messages">No message history found</p>';
        return;
    }
    
    messages.forEach((message, index) => {
        const messageElement = document.createElement('div');
        messageElement.className = `history-item ${message.type}`;
        messageElement.dataset.index = index;
        
        let icon, content;
        switch(message.type) {
            case 'encrypted':
                icon = '<i class="fas fa-lock message-icon"></i>';
                content = `Encrypted: ${message.content.substring(0, 30)}${message.content.length > 30 ? '...' : ''}`;
                break;
            case 'decrypted':
                icon = '<i class="fas fa-unlock message-icon"></i>';
                content = `Decrypted: ${message.content.substring(0, 30)}${message.content.length > 30 ? '...' : ''}`;
                break;
            case 'system':
                icon = '<i class="fas fa-cog message-icon"></i>';
                content = message.content;
                break;
        }
        
        const timeString = new Date(message.timestamp).toLocaleTimeString();
        
        messageElement.innerHTML = `
            ${icon}
            <div class="message-preview">
                <span>${content}</span>
                <span class="message-time">${timeString}</span>
            </div>
        `;
        
        messageHistory.appendChild(messageElement);
        messageElement.addEventListener('click', () => showMessageDetails(index));
    });
}

function showMessageDetails(index) {
    const message = messages[index];
    let details = "";
    
    switch(message.type) {
        case 'encrypted':
            details = `
                <h3><i class="fas fa-lock"></i> Encrypted Message</h3>
                <p class="timestamp">${new Date(message.timestamp).toLocaleString()}</p>
                <div class="message-detail">
                    <label>Original:</label>
                    <div class="message-content">${message.content}</div>
                </div>
                <div class="message-detail">
                    <label>Encrypted:</label>
                    <div class="message-content encrypted">${message.encrypted}</div>
                </div>
                ${message.burnAfter ? '<p class="warning"><i class="fas fa-exclamation-triangle"></i> Burn after reading enabled</p>' : ''}
                ${message.ttl ? `<p class="warning"><i class="fas fa-clock"></i> Self-destruct in ${message.ttl} minutes</p>` : ''}
            `;
            break;
        case 'decrypted':
            details = `
                <h3><i class="fas fa-unlock"></i> Decrypted Message</h3>
                <p class="timestamp">${new Date(message.timestamp).toLocaleString()}</p>
                <div class="message-detail">
                    <label>Encrypted:</label>
                    <div class="message-content encrypted">${message.encrypted}</div>
                </div>
                <div class="message-detail">
                    <label>Decrypted:</label>
                    <div class="message-content">${message.content}</div>
                </div>
            `;
            break;
        case 'system':
            details = `
                <h3><i class="fas fa-cog"></i> System Event</h3>
                <p class="timestamp">${new Date(message.timestamp).toLocaleString()}</p>
                <div class="message-content">${message.content}</div>
            `;
            break;
    }
    
    messageDetailsContent.innerHTML = details;
    messageModal.style.display = "block";
}

function clearHistory() {
    if (confirm("Are you sure you want to clear all message history? This cannot be undone.")) {
        messages = [];
        localStorage.removeItem('messageHistory');
        renderMessageHistory();
    }
}

// Self-Destruct Functionality
function setSelfDestruct(message) {
    if (!message) return;
    
    const ttl = message.ttl || 5;
    
    if (confirm(`Set self-destruct for this message in ${ttl} minutes?`)) {
        const destructTime = new Date().getTime() + (ttl * 60000);
        selfDestructTimers[message.encrypted] = setTimeout(() => {
            messages = messages.filter(m => m.encrypted !== message.encrypted);
            localStorage.setItem('messageHistory', JSON.stringify(messages));
            renderMessageHistory();
            
            if (encryptedText.value === message.encrypted) {
                encryptedText.value = "";
                decryptedText.value = "";
                document.getElementById('message-warning').textContent = "Message has self-destructed";
                document.getElementById('message-warning').style.display = "block";
            }
        }, ttl * 60000);
    }
}

// Threat Monitoring
function startThreatMonitoring() {
    updateThreatDisplay();
    
    setInterval(() => {
        if (Math.random() > 0.7) {
            threatLevelValue = Math.max(threatLevelValue - 5, 10);
            updateThreatDisplay();
        }
    }, 30000);
}

function updateThreatDisplay() {
    threatLevel.style.width = `${threatLevelValue}%`;
    
    if (threatLevelValue < 30) {
        threatLevel.style.backgroundColor = "var(--drdo-success)";
        threatStatus.textContent = "No active threats";
        threatStatus.style.color = "var(--drdo-success)";
        threatLevelText.textContent = "Low";
    } else if (threatLevelValue < 70) {
        threatLevel.style.backgroundColor = "var(--drdo-warning)";
        threatStatus.textContent = "Suspicious activity detected";
        threatStatus.style.color = "var(--drdo-warning)";
        threatLevelText.textContent = "Medium";
    } else {
        threatLevel.style.backgroundColor = "var(--drdo-error)";
        threatStatus.textContent = "CRITICAL THREAT LEVEL";
        threatStatus.style.color = "var(--drdo-error)";
        threatStatus.classList.add('alert-pulse');
        threatLevelText.textContent = "High";
    }
}

// Emergency Protocols
function lockSystem() {
    emergencyProtocolActive = true;
    localStorage.setItem('emergencyLock', 'true');
    alert("SYSTEM LOCKED: All functions disabled until supervisor authorization");
    logout();
    emergencyModal.style.display = "none";
    
    addToMessageHistory({
        type: 'system',
        content: 'System locked by user',
        timestamp: new Date().toISOString()
    });
}

function wipeData() {
    if (confirm("WARNING: This will permanently delete all message history and clear all data. Continue?")) {
        messages = [];
        localStorage.removeItem('messageHistory');
        renderMessageHistory();
        
        plaintext.value = "";
        ciphertext.value = "";
        encryptedText.value = "";
        decryptedText.value = "";
        
        alert("All data has been securely wiped");
        emergencyModal.style.display = "none";
        
        addToMessageHistory({
            type: 'system',
            content: 'All data wiped by user',
            timestamp: new Date().toISOString()
        });
    }
}

function activateDecoy() {
    document.body.innerHTML = `
        <div style="padding: 2rem; text-align: center;">
            <h1>Windows Update</h1>
            <p>Your computer is being updated. Do not turn off your computer.</p>
            <div style="width: 100%; background: #f0f0f0; border-radius: 4px; margin: 1rem 0;">
                <div id="update-progress" style="height: 20px; background: #0066cc; width: 5%; border-radius: 4px;"></div>
            </div>
            <p id="update-percent">5% complete</p>
        </div>
    `;
    
    let progress = 5;
    const progressInterval = setInterval(() => {
        progress += Math.random() * 10;
        if (progress >= 100) {
            progress = 100;
            clearInterval(progressInterval);
        }
        document.getElementById('update-progress').style.width = `${progress}%`;
        document.getElementById('update-percent').textContent = `${Math.floor(progress)}% complete`;
    }, 1000);
    
    addToMessageHistory({
        type: 'system',
        content: 'Decoy screen activated',
        timestamp: new Date().toISOString()
    });
}

function showEmergencyLockdown() {
    alert("SYSTEM LOCKED: Emergency protocols active. All functions disabled.");
}

function renderEmergencyContacts() {
    emergencyContactsList.innerHTML = '';
    EMERGENCY_CONTACTS.forEach(contact => {
        const contactElement = document.createElement('div');
        contactElement.className = 'emergency-contact';
        contactElement.innerHTML = `
            <div class="contact-name">${contact.name}</div>
            <div class="contact-number">${contact.number}</div>
            <button class="btn btn-small contact-btn" data-number="${contact.number}">
                <i class="fas fa-phone"></i> Call
            </button>
        `;
        emergencyContactsList.appendChild(contactElement);
    });
}

// Theme Toggle
function toggleTheme() {
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
}

// Logout
function logout() {
    appContainer.style.display = "none";
    pinContainer.style.display = "flex";
    pinInput.value = "";
    pinInput.focus();
    clearEncryptFields();
    clearDecryptFields();
}

// Clear Functions
function clearEncryptFields() {
    plaintext.value = "";
    ciphertext.value = "";
}

function clearDecryptFields() {
    encryptedText.value = "";
    decryptedText.value = "";
    document.getElementById('message-warning').style.display = "none";
}

// Event Listeners Setup
function setupEventListeners() {
    // Authentication
    pinSubmit.addEventListener('click', authenticate);
    pinInput.addEventListener('keypress', (e) => e.key === 'Enter' && authenticate());
    
    // Theme
    themeToggle.addEventListener('change', toggleTheme);
    
    // Navigation
    logoutBtn.addEventListener('click', logout);
    emergencyBtn.addEventListener('click', () => {
        emergencyModal.style.display = "block";
        emergencyModal.querySelector('.modal-content').scrollTop = 0;
    });
    
    // Emergency actions
    lockSystemBtn.addEventListener('click', lockSystem);
    wipeDataBtn.addEventListener('click', wipeData);
    fakeScreenBtn.addEventListener('click', activateDecoy);
    wipeKeysBtn.addEventListener('click', wipeKeyVault);
    
    // Modals
    closeModal.forEach(btn => btn.addEventListener('click', () => {
        document.querySelectorAll('.modal').forEach(m => m.style.display = "none");
    }));
    
    // Messaging
    encryptBtn.addEventListener('click', encryptMessage);
    decryptBtn.addEventListener('click', decryptMessage);
    clearEncrypt.addEventListener('click', clearEncryptFields);
    clearDecrypt.addEventListener('click', clearDecryptFields);
    selfDestructBtn.addEventListener('click', () => {
        const message = {
            encrypted: encryptedText.value,
            content: plaintext.value,
            ttl: ttlInput.value ? parseInt(ttlInput.value) : 5
        };
        setSelfDestruct(message);
    });
    
    // History
    clearHistoryBtn.addEventListener('click', clearHistory);
    
    // Links
    privacyLink.addEventListener('click', (e) => {
        e.preventDefault();
        alert("Privacy Policy: All communications are encrypted end-to-end. No messages are stored on our servers.");
    });
    termsLink.addEventListener('click', (e) => {
        e.preventDefault();
        alert("Terms of Service: This system is for authorized use only. Unauthorized access is prohibited.");
    });
    contactLink.addEventListener('click', (e) => {
        e.preventDefault();
        alert("Contact Support: For assistance, use your designated secure channels.");
    });
    
    // File encryption
    fileEncryptionBtn.addEventListener('click', () => {
        fileModal.style.display = "block";
        fileModal.querySelector('.modal-content').scrollTop = 0;
    });
    
    // Key generation
    document.getElementById('generate-key-checkbox').addEventListener('change', (e) => {
        document.getElementById('generate-key-btn').disabled = !e.target.checked;
    });
    document.getElementById('generate-key-btn').addEventListener('click', generateNewKey);
    document.getElementById('copy-key-btn').addEventListener('click', () => {
        navigator.clipboard.writeText(document.getElementById('security-key').textContent);
        showFileStatus(document.getElementById('file-encryption-status'), "Key copied to clipboard!", "success");
    });
    
    // File operations
    document.getElementById('file-to-encrypt').addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            document.getElementById('encrypt-file-btn').disabled = false;
            showFileStatus(document.getElementById('file-encryption-status'), `Ready to encrypt: ${file.name}`, "ready");
            
            if (document.getElementById('generate-key-checkbox').checked) {
                generateNewKey();
            }
        }
    });
    
    document.getElementById('encrypt-file-btn').addEventListener('click', handleFileEncryption);
    
    document.getElementById('file-to-decrypt').addEventListener('change', (e) => {
        if (e.target.files.length > 0 && document.getElementById('decryption-key').value.trim()) {
            document.getElementById('decrypt-file-btn').disabled = false;
        }
    });
    
    document.getElementById('decryption-key').addEventListener('input', (e) => {
        if (document.getElementById('file-to-decrypt').files.length > 0 && e.target.value.trim()) {
            document.getElementById('decrypt-file-btn').disabled = false;
        }
    });
    
    document.getElementById('paste-key-btn').addEventListener('click', async () => {
        try {
            const text = await navigator.clipboard.readText();
            document.getElementById('decryption-key').value = text;
            if (document.getElementById('file-to-decrypt').files.length > 0) {
                document.getElementById('decrypt-file-btn').disabled = false;
            }
        } catch (error) {
            alert("Failed to read from clipboard. Please paste manually.");
        }
    });
    
    document.getElementById('decrypt-file-btn').addEventListener('click', handleFileDecryption);
    
    // Key vault
    keyVaultBtn.addEventListener('click', () => {
        keyVaultModal.style.display = "block";
    });
    
    document.getElementById('export-keys-btn').addEventListener('click', exportKeys);
    document.getElementById('import-keys-btn').addEventListener('click', importKeys);
    document.getElementById('wipe-vault-btn').addEventListener('click', wipeKeyVault);
    
    // Check for emergency lock on load
    if (localStorage.getItem('emergencyLock') === 'true') {
        emergencyProtocolActive = true;
        showEmergencyLockdown();
    }
    
    // Keyboard Shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl+E for encrypt
        if (e.ctrlKey && e.key === 'e') {
            e.preventDefault();
            encryptMessage();
        }
        
        // Ctrl+D for decrypt
        if (e.ctrlKey && e.key === 'd') {
            e.preventDefault();
            decryptMessage();
        }
        
        // Ctrl+L for logout
        if (e.ctrlKey && e.key === 'l') {
            e.preventDefault();
            logout();
        }
        
        // Ctrl+T for theme toggle
        if (e.ctrlKey && e.key === 't') {
            e.preventDefault();
            themeToggle.click();
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal').forEach(m => m.style.display = "none");
        }
        
        // Emergency shortcut (Ctrl+Alt+E)
        if (e.ctrlKey && e.altKey && e.key === 'e') {
            e.preventDefault();
            emergencyModal.style.display = "block";
        }
        
        // File encryption shortcut (Ctrl+Alt+F)
        if (e.ctrlKey && e.altKey && e.key === 'f') {
            e.preventDefault();
            fileModal.style.display = "block";
        }
        
        // Key vault shortcut (Ctrl+Alt+K)
        if (e.ctrlKey && e.altKey && e.key === 'k') {
            e.preventDefault();
            keyVaultModal.style.display = "block";
        }
    });
}