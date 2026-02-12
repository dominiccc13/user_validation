const key = document.getElementById('plain-key');
const submitKeyBtn = document.getElementById('submit-key-btn');
submitKeyBtn.addEventListener('click', async () => {getEncryptionKey(key.value, '661330')})

async function getSalt(username) {
    
}

async function getEncryptionKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", encoder.encode(masterPassword), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: encoder.encode(salt), iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]
    );
}

async function encrypt(plainText, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // Unique every time
    const encoded = new TextEncoder().encode(plainText);
    
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, encoded
    );

    return {
        encryptedData: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        iv: btoa(String.fromCharCode(...iv))
    };
}

async function decrypt(encryptedDataB64, ivB64, key) {
    const data = Uint8Array.from(atob(encryptedDataB64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, key, data
    );
    return new TextDecoder().decode(decrypted);
}