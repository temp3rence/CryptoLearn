// ========= DOM-элементы =========

const passwordEl          = document.getElementById('password');
const filenameEl          = document.getElementById('filename');
const plaintextEl         = document.getElementById('plaintext');
const encryptedEl         = document.getElementById('encrypted');
const plaintextPreviewEl  = document.getElementById('plaintext-preview');
const statusEl            = document.getElementById('status');
const historyBox          = document.getElementById('historyBox');
const adminSummaryBox     = document.getElementById('adminSummaryBox');
const sessionIdBox        = document.getElementById('sessionIdBox');

const btnEncrypt          = document.getElementById('btn-encrypt');
const btnEncryptFile      = document.getElementById('btn-encrypt-file');
const btnDecrypt          = document.getElementById('btn-decrypt');
const btnDecryptFile      = document.getElementById('btn-decrypt-file');
const btnHistory          = document.getElementById('btn-history');
const btnAdminSummary     = document.getElementById('btn-admin-summary');
const fileInput           = document.getElementById('fileInput');

// ========= localStorage ключи =========

const SESSION_KEY        = "safeboxSessionId";
const LAST_PLAIN_KEY     = "safeboxLastPlaintext";
const LAST_ENCRYPTED_KEY = "safeboxLastEncrypted";

// ========= Вспомогательные =========

function setStatus(msg) {
    statusEl.textContent = msg;
}

function generateSessionId() {
    if (window.crypto && window.crypto.randomUUID) {
        return window.crypto.randomUUID();
    }
    return "sess-" + Math.random().toString(16).slice(2) + "-" + Date.now();
}

// простые base64-helpers для текстового режима
function toBase64(str) {
    return btoa(str);
}

function fromBase64(b64) {
    return atob(b64);
}

// base64 <-> bytes для бинарного режима
function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToBytes(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

async function callApi(path, payload) {
    const res = await fetch(path, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Session-Id": window.safeboxSessionId
        },
        body: JSON.stringify(payload)
    });
    const body = await res.json();
    return { res, body };
}

// ========= Инициализация сессии =========

(function initSession() {
    let sessionId = localStorage.getItem(SESSION_KEY);
    if (!sessionId) {
        sessionId = generateSessionId();
        localStorage.setItem(SESSION_KEY, sessionId);
    }
    window.safeboxSessionId = sessionId;
    sessionIdBox.textContent = sessionId;

    const lastPlain = localStorage.getItem(LAST_PLAIN_KEY);
    if (lastPlain !== null) {
        plaintextEl.value = lastPlain;
    }

    const lastEncrypted = localStorage.getItem(LAST_ENCRYPTED_KEY);
    if (lastEncrypted !== null) {
        encryptedEl.value = lastEncrypted;
    }
})();

// ========= Обработчики =========

// ENCRYPT TEXT
btnEncrypt.addEventListener('click', async () => {
    const password  = passwordEl.value;
    const filename  = filenameEl.value || "input.txt";
    const plaintext = plaintextEl.value;

    if (!password) {
        setStatus("ERROR: password is empty");
        return;
    }
    if (!plaintext) {
        setStatus("ERROR: plaintext is empty");
        return;
    }

    const plaintextBase64 = toBase64(plaintext);
    const payload = { password, plaintextBase64, filename };

    try {
        setStatus("Encrypting text...");
        const { res, body } = await callApi("/api/safebox/encrypt", payload);

        if (!res.ok || body.status !== "SUCCESS") {
            setStatus("ERROR: " + (body.errorCode || "UNKNOWN") + "\n" + (body.message || ""));
            return;
        }

        encryptedEl.value = body.encryptedFileBase64 || "";
        localStorage.setItem(LAST_PLAIN_KEY, plaintext);
        localStorage.setItem(LAST_ENCRYPTED_KEY, encryptedEl.value);

        setStatus(
            "Encrypt TEXT SUCCESS\n" +
            "filename=" + body.filename + "\n" +
            "durationMs=" + body.durationMs + "\n" +
            "httpStatus=" + res.status
        );
    } catch (e) {
        console.error(e);
        setStatus("ERROR: " + e);
    }
});

// ENCRYPT FILE
btnEncryptFile.addEventListener('click', async () => {
    const password = passwordEl.value;
    const file = fileInput.files[0];

    if (!password) {
        setStatus("ERROR: password is empty");
        return;
    }
    if (!file) {
        setStatus("ERROR: no file selected");
        return;
    }

    // ограничение по размеру — тот же порядок, что и на сервере (MAX_BODY_BYTES ≈ 5MB)
    const maxBytes = 5 * 1024 * 1024;
    if (file.size > maxBytes) {
        setStatus("ERROR: file is too large (>" + maxBytes + " bytes)");
        return;
    }

    const reader = new FileReader();

    reader.onload = async () => {
        try {
            const arrayBuffer = reader.result;
            const bytes = new Uint8Array(arrayBuffer);
            const plaintextBase64 = bytesToBase64(bytes);

            const filename = file.name || "file.bin";
            const payload = { password, plaintextBase64, filename };

            setStatus("Encrypting file...");
            const { res, body } = await callApi("/api/safebox/encrypt", payload);

            if (!res.ok || body.status !== "SUCCESS") {
                setStatus("ERROR: " + (body.errorCode || "UNKNOWN") + "\n" + (body.message || ""));
                return;
            }

            encryptedEl.value = body.encryptedFileBase64 || "";
            localStorage.setItem(LAST_PLAIN_KEY, "(binary file: " + filename + ")");
            localStorage.setItem(LAST_ENCRYPTED_KEY, encryptedEl.value);

            setStatus(
                "Encrypt FILE SUCCESS\n" +
                "filename=" + body.filename + "\n" +
                "fileSize=" + file.size + " bytes\n" +
                "durationMs=" + body.durationMs + "\n" +
                "httpStatus=" + res.status
            );
        } catch (e) {
            console.error(e);
            setStatus("ERROR during file encrypt: " + e);
        }
    };

    reader.onerror = () => {
        setStatus("ERROR: failed to read file");
    };

    reader.readAsArrayBuffer(file);
});

// DECRYPT → TEXT
btnDecrypt.addEventListener('click', async () => {
    const password   = passwordEl.value;
    const filename   = filenameEl.value || "output.txt";
    const encBase64  = encryptedEl.value.trim();

    if (!password) {
        setStatus("ERROR: password is empty");
        return;
    }
    if (!encBase64) {
        setStatus("ERROR: encryptedFileBase64 is empty");
        return;
    }

    const payload = { password, encryptedFileBase64: encBase64, filename };

    try {
        setStatus("Decrypting to text...");
        const { res, body } = await callApi("/api/safebox/decrypt", payload);

        if (!res.ok || body.status !== "SUCCESS") {
            setStatus("ERROR: " + (body.errorCode || "UNKNOWN") + "\n" + (body.message || ""));
            return;
        }

        const plaintext = fromBase64(body.plaintextBase64 || "");
        plaintextPreviewEl.value = plaintext;

        localStorage.setItem(LAST_PLAIN_KEY, plaintext);
        localStorage.setItem(LAST_ENCRYPTED_KEY, encBase64);

        setStatus(
            "Decrypt TEXT SUCCESS\n" +
            "filename=" + body.filename + "\n" +
            "durationMs=" + body.durationMs + "\n" +
            "httpStatus=" + res.status
        );
    } catch (e) {
        console.error(e);
        setStatus("ERROR: " + e);
    }
});

// DECRYPT → FILE (скачать)
btnDecryptFile.addEventListener('click', async () => {
    const password   = passwordEl.value;
    const filename   = filenameEl.value || "output.bin";
    const encBase64  = encryptedEl.value.trim();

    if (!password) {
        setStatus("ERROR: password is empty");
        return;
    }
    if (!encBase64) {
        setStatus("ERROR: encryptedFileBase64 is empty");
        return;
    }

    const payload = { password, encryptedFileBase64: encBase64, filename };

    try {
        setStatus("Decrypting to file...");
        const { res, body } = await callApi("/api/safebox/decrypt", payload);

        if (!res.ok || body.status !== "SUCCESS") {
            setStatus("ERROR: " + (body.errorCode || "UNKNOWN") + "\n" + (body.message || ""));
            return;
        }

        const plainBytes = base64ToBytes(body.plaintextBase64 || "");
        const blob = new Blob([plainBytes], { type: "application/octet-stream" });
        const downloadName = body.filename || filename || "output.bin";

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = downloadName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        setStatus(
            "Decrypt FILE SUCCESS\n" +
            "filename=" + downloadName + "\n" +
            "size=" + plainBytes.length + " bytes\n" +
            "durationMs=" + body.durationMs + "\n" +
            "httpStatus=" + res.status
        );
    } catch (e) {
        console.error(e);
        setStatus("ERROR: " + e);
    }
});

// HISTORY
btnHistory.addEventListener('click', async () => {
    try {
        setStatus("Loading history...");
        const res = await fetch("/api/operations?limit=20");
        const body = await res.json();

        if (!res.ok) {
            setStatus("ERROR loading history: " + (body.message || res.status));
            return;
        }

        historyBox.textContent = JSON.stringify(body, null, 2);
        setStatus("History loaded (" + body.length + " operations)");
    } catch (e) {
        console.error(e);
        setStatus("ERROR loading history: " + e);
    }
});

// ADMIN SUMMARY
btnAdminSummary.addEventListener('click', async () => {
    try {
        setStatus("Loading admin summary...");
        const res = await fetch("/api/admin/summary");
        const body = await res.json();

        if (!res.ok) {
            setStatus("ERROR loading summary: " + (body.message || res.status));
            return;
        }

        adminSummaryBox.textContent = JSON.stringify(body, null, 2);
        setStatus("Summary loaded");
    } catch (e) {
        console.error(e);
        setStatus("ERROR loading summary: " + e);
    }
});
