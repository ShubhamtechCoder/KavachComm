// Security Configuration
const SECRET_PIN = "2024"; // Change this in production
const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 5 * 60 * 1000; // 5 minutes

// State Management
let attempts = 0;
let lockoutUntil = 0;

// DOM Elements
const pinContainer = document.getElementById('pin-container');
const appContainer = document.getElementById('app-container');
const pinInput = document.getElementById('pin-input');
const pinSubmit = document.getElementById('pin-submit');
const pinError = document.getElementById('pin-error');
const lastAuth = document.getElementById('last-auth');
const themeToggle = document.getElementById('theme-toggle');
const toggleIcon = document.getElementById('toggle-icon');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkLockoutStatus();
    initTheme();
    pinInput.focus();
});

// Theme Management
function initTheme() {
    const savedTheme = localStorage.getItem('kavach-theme') || 
                      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    setTheme(savedTheme);
}

themeToggle.addEventListener('change', (e) => {
    const newTheme = e.target.checked ? 'dark' : 'light';
    setTheme(newTheme);
    localStorage.setItem('kavach-theme', newTheme);
});

function setTheme(theme) {
    document.body.className = `${theme}-mode`;
    themeToggle.checked = theme === 'dark';
    toggleIcon.innerHTML = theme === 'dark' ? 
        '<i class="fas fa-moon"></i>' : 
        '<i class="fas fa-sun"></i>';
}

// Security Functions
function checkLockoutStatus() {
    const now = Date.now();
    if (now < lockoutUntil) {
        const minutesLeft = Math.ceil((lockoutUntil - now) / 60000);
        disablePINInput(`System locked. Try again in ${minutesLeft} minute(s)`);
        setTimeout(checkLockoutStatus, 60000); // Check every minute
    } else if (attempts >= MAX_ATTEMPTS) {
        resetAttempts();
    }
}

function disablePINInput(message) {
    pinInput.disabled = true;
    pinSubmit.disabled = true;
    pinError.textContent = message;
    pinError.style.color = "var(--error)";
}

function enablePINInput() {
    pinInput.disabled = false;
    pinSubmit.disabled = false;
    pinInput.value = "";
    pinInput.focus();
    pinError.textContent = "";
}

function resetAttempts() {
    attempts = 0;
    lockoutUntil = 0;
    enablePINInput();
}

// Authentication
pinSubmit.addEventListener('click', authenticate);
pinInput.addEventListener('keypress', (e) => e.key === 'Enter' && authenticate());

function authenticate() {
    const now = Date.now();
    
    if (now < lockoutUntil) {
        const minutesLeft = Math.ceil((lockoutUntil - now) / 60000);
        pinError.textContent = `System locked. Try again in ${minutesLeft} minute(s)`;
        return;
    }

    const enteredPin = pinInput.value.trim();
    
    if (enteredPin === SECRET_PIN) {
        resetAttempts();
        pinError.textContent = "";
        pinContainer.style.display = "none";
        appContainer.style.display = "block";
        lastAuth.textContent = new Date().toLocaleString();
        appContainer.classList.add('fade-in');
    } else {
        attempts++;
        const remaining = MAX_ATTEMPTS - attempts;
        pinError.textContent = remaining > 0 ? 
            `Invalid code. ${remaining} attempt(s) remaining` : 
            "Maximum attempts reached";
        pinInput.value = "";
        
        if (attempts >= MAX_ATTEMPTS) {
            lockoutUntil = now + LOCKOUT_DURATION;
            disablePINInput("Security lock activated. System temporarily disabled.");
            setTimeout(checkLockoutStatus, 60000);
        }
    }
}

// Encryption Functions
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const plaintext = document.getElementById('plaintext');
const ciphertext = document.getElementById('ciphertext');
const encryptedText = document.getElementById('encrypted-text');
const decryptedText = document.getElementById('decrypted-text');
const encryptLoading = document.getElementById('encrypt-loading');
const decryptLoading = document.getElementById('decrypt-loading');
const clearEncrypt = document.getElementById('clear-encrypt');
const clearDecrypt = document.getElementById('clear-decrypt');

function processWithDelay(input, output, loading, processFn) {
    if (!input.value.trim()) {
        alert("Please enter a message");
        return;
    }
    
    loading.style.display = "block";
    output.value = "";
    
    setTimeout(() => {
        output.value = processFn(input.value);
        loading.style.display = "none";
    }, 800);
}

function encryptMessage(text) {
    return btoa(unescape(encodeURIComponent(text)));
}

function decryptMessage(text) {
    try {
        return decodeURIComponent(escape(atob(text)));
    } catch {
        return "ERROR: Invalid message format";
    }
}

encryptBtn.addEventListener('click', () => 
    processWithDelay(plaintext, ciphertext, encryptLoading, encryptMessage));

decryptBtn.addEventListener('click', () => 
    processWithDelay(encryptedText, decryptedText, decryptLoading, decryptMessage));

clearEncrypt.addEventListener('click', () => {
    plaintext.value = "";
    ciphertext.value = "";
});

clearDecrypt.addEventListener('click', () => {
    encryptedText.value = "";
    decryptedText.value = "";
});