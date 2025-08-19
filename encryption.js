// encryption.js
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

// ── Load or generate key ─────────────────────────────
function loadKey() {
    let key = process.env.FERNET_KEY;
    const keyPath = process.env.FERNET_KEY_PATH || path.join(__dirname, "fernet.key");

    if (!key) {
        if (fs.existsSync(keyPath)) {
            key = fs.readFileSync(keyPath, "utf-8").trim();
        } else {
            key = crypto.randomBytes(32).toString("hex"); // 256-bit key
            try {
                fs.writeFileSync(keyPath, key);
                console.log(`Generated Fernet key at ${keyPath} (dev use).`);
            } catch (err) {
                console.log("Could not write fernet.key; using in-memory key only.");
            }
        }
    }
    return Buffer.from(key, "hex");
}

const key = loadKey();

// ── Encrypt & Decrypt ───────────────────────────────
function encryptText(plain) {
    if (!plain) plain = "";
    const iv = crypto.randomBytes(16); // Initialization vector
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(plain, "utf8", "base64");
    encrypted += cipher.final("base64");
    const result = iv.toString("base64") + ":" + encrypted; // prepend IV
    return result;
}

function decryptText(token) {
    try {
        const [ivBase64, encryptedData] = token.split(":");
        const iv = Buffer.from(ivBase64, "base64");
        const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
        let decrypted = decipher.update(encryptedData, "base64", "utf8");
        decrypted += decipher.final("utf8");
        return decrypted;
    } catch (err) {
        return ""; // invalid token
    }
}

// ── Export ─────────────────────────────
module.exports = { encryptText, decryptText };
