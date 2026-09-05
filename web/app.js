// UI Elements
const tabEncrypt = document.getElementById('tab-encrypt');
const tabDecrypt = document.getElementById('tab-decrypt');
const messageLabel = document.getElementById('message-label');
const messageInput = document.getElementById('message-input');
const keyInput = document.getElementById('key-input');
const actionBtn = document.getElementById('action-btn');
const clearBtn = document.getElementById('clear-btn');
const resultOutput = document.getElementById('result-output');
const copyBtn = document.getElementById('copy-btn');
const toggleVisBtn = document.getElementById('toggle-visibility');

let currentMode = 'encrypt'; // 'encrypt' or 'decrypt'

// Stroke-based SVG Icons (consistent 2px stroke, geometric linecap/linejoin)
const ICONS = {
    lock: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`,
    unlock: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>`,
    eye: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle></svg>`,
    eyeOff: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"></path><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"></path><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"></path><line x1="2" x2="22" y1="2" y2="22"></line></svg>`,
    copy: `<svg class="copy-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`,
    check: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`
};

// --- Crypto Functions ---

// Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Convert Base64 to Uint8Array
function base64ToUint8Array(base64) {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

// Derive AES key using PBKDF2 (100,000 iterations, SHA-256)
async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// Encrypt v2 format: salt(16) + iv(12) + tag(16) + ciphertext
async function encryptMessage(text, password) {
    const enc = new TextEncoder();
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const key = await deriveKey(password, salt);
    
    const encryptedContent = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        enc.encode(text)
    );
    
    const encryptedBytes = new Uint8Array(encryptedContent);
    const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
    const tag = encryptedBytes.slice(encryptedBytes.length - 16);
    
    const combined = new Uint8Array(16 + 12 + 16 + ciphertext.length);
    combined.set(salt, 0);
    combined.set(iv, 16);
    combined.set(tag, 28);
    combined.set(ciphertext, 44);
    
    return "v2:" + arrayBufferToBase64(combined);
}

// Decrypt v2 format
async function decryptMessage(encryptedText, password) {
    if (!encryptedText.startsWith("v2:")) {
        throw new Error("Only v2 encrypted messages are supported on the web version.");
    }
    
    const base64Data = encryptedText.substring(3);
    const data = base64ToUint8Array(base64Data);
    
    if (data.length < 44) {
        throw new Error("Invalid encrypted payload format.");
    }
    
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const tag = data.slice(28, 44);
    const ciphertext = data.slice(44);
    
    const ciphertextAndTag = new Uint8Array(ciphertext.length + 16);
    ciphertextAndTag.set(ciphertext, 0);
    ciphertextAndTag.set(tag, ciphertext.length);
    
    const key = await deriveKey(password, salt);
    
    try {
        const decryptedContent = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            ciphertextAndTag
        );
        
        const dec = new TextDecoder();
        return dec.decode(decryptedContent);
    } catch (e) {
        throw new Error("Decryption failed. Please check your key and try again.");
    }
}

// --- UI Logic ---

// Tab Switching
tabEncrypt.addEventListener('click', () => {
    currentMode = 'encrypt';
    tabEncrypt.classList.add('active');
    tabDecrypt.classList.remove('active');
    messageLabel.innerText = 'Enter Text to Encrypt';
    messageInput.placeholder = 'Enter your secret message here...';
    
    actionBtn.querySelector('.btn-icon').innerHTML = ICONS.lock;
    actionBtn.querySelector('.btn-text').textContent = 'ENCRYPT';
    actionBtn.classList.remove('decrypt-mode');
});

tabDecrypt.addEventListener('click', () => {
    currentMode = 'decrypt';
    tabDecrypt.classList.add('active');
    tabEncrypt.classList.remove('active');
    messageLabel.innerText = 'Enter Ciphertext to Decrypt';
    messageInput.placeholder = 'Paste encrypted text here (starts with v2:)...';
    
    actionBtn.querySelector('.btn-icon').innerHTML = ICONS.unlock;
    actionBtn.querySelector('.btn-text').textContent = 'DECRYPT';
    actionBtn.classList.add('decrypt-mode');
});

// Toggle Password Visibility
toggleVisBtn.addEventListener('click', () => {
    const isPassword = keyInput.getAttribute('type') === 'password';
    keyInput.setAttribute('type', isPassword ? 'text' : 'password');
    toggleVisBtn.innerHTML = isPassword ? ICONS.eyeOff : ICONS.eye;
});

// Clear All
clearBtn.addEventListener('click', () => {
    messageInput.value = '';
    keyInput.value = '';
    resultOutput.value = '';
    resultOutput.className = '';
    messageInput.focus();
});

// Copy Result
copyBtn.addEventListener('click', () => {
    if (resultOutput.value) {
        navigator.clipboard.writeText(resultOutput.value).then(() => {
            copyBtn.innerHTML = ICONS.check;
            setTimeout(() => {
                copyBtn.innerHTML = ICONS.copy;
            }, 1800);
        });
    }
});

// Perform Action (Encrypt/Decrypt)
actionBtn.addEventListener('click', async () => {
    const text = messageInput.value.trim();
    const key = keyInput.value;
    
    if (!text || !key) {
        alert("Please provide both the message and encryption key.");
        return;
    }
    
    resultOutput.className = '';
    
    try {
        if (currentMode === 'encrypt') {
            const encrypted = await encryptMessage(text, key);
            resultOutput.value = encrypted;
            resultOutput.classList.add('has-content', 'text-error');
        } else {
            const decrypted = await decryptMessage(text, key);
            resultOutput.value = decrypted;
            resultOutput.classList.add('has-content', 'text-success');
        }
    } catch (err) {
        alert(err.message);
        resultOutput.value = '';
        resultOutput.classList.remove('has-content');
    }
});
