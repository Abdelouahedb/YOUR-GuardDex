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

// Derive AES key using PBKDF2
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
    
    // WebCrypto returns ciphertext + tag appended.
    // Our Python code structure: salt (16) + iv (12) + tag (16) + ciphertext (N)
    // Actually in cryptography.hazmat, AES-GCM output is just ciphertext. The tag is separate.
    // In our Python `encrypt_v2`: encrypted_data = salt + iv + encryptor.tag + ciphertext
    
    const encryptedBytes = new Uint8Array(encryptedContent);
    
    // In Web Crypto, AES-GCM appends the 16-byte authentication tag to the END of the ciphertext.
    // So `encryptedBytes` = ciphertext + tag.
    // We need to rearrange it to: salt + iv + tag + ciphertext to match Python's format.
    
    const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
    const tag = encryptedBytes.slice(encryptedBytes.length - 16);
    
    const combined = new Uint8Array(16 + 12 + 16 + ciphertext.length);
    combined.set(salt, 0);
    combined.set(iv, 16);
    combined.set(tag, 28);
    combined.set(ciphertext, 44);
    
    return "v2:" + arrayBufferToBase64(combined);
}

async function decryptMessage(encryptedText, password) {
    if (!encryptedText.startsWith("v2:")) {
        throw new Error("Only v2 encrypted messages are supported on the web version.");
    }
    
    const base64Data = encryptedText.substring(3);
    const data = base64ToUint8Array(base64Data);
    
    if (data.length < 44) {
        throw new Error("Invalid encrypted data format.");
    }
    
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const tag = data.slice(28, 44);
    const ciphertext = data.slice(44);
    
    // Web Crypto expects ciphertext + tag for decryption
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
        throw new Error("Decryption failed! Check your key.");
    }
}

// --- UI Logic ---

// Tab Switching
tabEncrypt.addEventListener('click', () => {
    currentMode = 'encrypt';
    tabEncrypt.classList.add('active');
    tabDecrypt.classList.remove('active');
    messageLabel.innerText = 'Enter Text to Encrypt:';
    messageInput.placeholder = 'Enter your secret message here...';
    actionBtn.innerHTML = '<i class="fa-solid fa-lock"></i> ENCRYPT';
    actionBtn.classList.remove('decrypt-mode');
});

tabDecrypt.addEventListener('click', () => {
    currentMode = 'decrypt';
    tabDecrypt.classList.add('active');
    tabEncrypt.classList.remove('active');
    messageLabel.innerText = 'Enter Text to Decrypt:';
    messageInput.placeholder = 'Paste encrypted text here (starts with v2:)...';
    actionBtn.innerHTML = '<i class="fa-solid fa-unlock"></i> DECRYPT';
    actionBtn.classList.add('decrypt-mode');
});

// Toggle Password Visibility
toggleVisBtn.addEventListener('click', () => {
    const type = keyInput.getAttribute('type') === 'password' ? 'text' : 'password';
    keyInput.setAttribute('type', type);
    toggleVisBtn.innerHTML = type === 'password' ? '<i class="fa-solid fa-eye"></i>' : '<i class="fa-solid fa-eye-slash"></i>';
});

// Clear All
clearBtn.addEventListener('click', () => {
    messageInput.value = '';
    keyInput.value = '';
    resultOutput.value = '';
    resultOutput.className = '';
});

// Copy Result
copyBtn.addEventListener('click', () => {
    if (resultOutput.value) {
        navigator.clipboard.writeText(resultOutput.value).then(() => {
            const originalHtml = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="fa-solid fa-check text-success"></i>';
            setTimeout(() => {
                copyBtn.innerHTML = originalHtml;
            }, 2000);
        });
    }
});

// Perform Action (Encrypt/Decrypt)
actionBtn.addEventListener('click', async () => {
    const text = messageInput.value.trim();
    const key = keyInput.value;
    
    if (!text || !key) {
        alert("Please provide both text and key.");
        return;
    }
    
    resultOutput.className = '';
    
    try {
        if (currentMode === 'encrypt') {
            const encrypted = await encryptMessage(text, key);
            resultOutput.value = encrypted;
            resultOutput.classList.add('text-error');
        } else {
            const decrypted = await decryptMessage(text, key);
            resultOutput.value = decrypted;
            resultOutput.classList.add('text-success');
        }
    } catch (err) {
        alert("Error: " + err.message);
        resultOutput.value = '';
    }
});
