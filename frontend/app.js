const API_URL = window.location.origin;

// State
let currentUser = null;
let authToken = null;
let signingKeyPair = null; // ECDSA
let encryptionKeyPair = null; // RSA-OAEP
let currentFolderId = null; // Current folder context

// DOM Elements
const authView = document.getElementById("auth-view");
const dashboardView = document.getElementById("dashboard-view");
const usernameInput = document.getElementById("username-input");
const authStatus = document.getElementById("auth-status");
const fileList = document.getElementById("file-list");
const fileInput = document.getElementById("file-input");
const dropZone = document.getElementById("drop-zone");
const uploadProgress = document.getElementById("upload-progress");
const btnCreateFolder = document.getElementById("btn-create-folder");
const modalCreateFolder = document.getElementById("create-folder-modal");
const inputFolderName = document.getElementById("new-folder-name");
const btnFolderCancel = document.getElementById("btn-folder-cancel");
const btnFolderCreate = document.getElementById("btn-folder-create");
const breadcrumbsContainer = document.getElementById("breadcrumbs");

// Tabs
const tabFiles = document.getElementById("tab-files");
const tabShared = document.getElementById("tab-shared");
const tabManage = document.getElementById("tab-manage");
const viewFiles = document.getElementById("view-files");
const viewShared = document.getElementById("view-shared");
const viewManage = document.getElementById("view-manage");
const tabSecurity = document.getElementById("tab-security");
const viewSecurity = document.getElementById("view-security");

// --- Toast Notification System ---

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');

    const colors = {
        success: 'bg-green-600 border-green-500',
        error: 'bg-red-600 border-red-500',
        warning: 'bg-yellow-600 border-yellow-500',
        info: 'bg-blue-600 border-blue-500'
    };

    toast.className = `${colors[type]} border-l-4 p-4 rounded-lg shadow-lg text-white animate-slide-in-right`;
    toast.innerHTML = `
        <div class="flex items-start gap-3">
            <div class="flex-1">
                <p class="text-sm font-medium">${message}</p>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" class="text-white/80 hover:text-white">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
            </button>
        </div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

function showConfirm(message, onConfirm, onCancel) {
    const modal = document.getElementById('confirm-modal');
    const messageEl = document.getElementById('confirm-message');
    const yesBtn = document.getElementById('btn-confirm-yes');
    const cancelBtn = document.getElementById('btn-confirm-cancel');

    messageEl.textContent = message;
    modal.classList.remove('hidden');

    yesBtn.onclick = () => {
        modal.classList.add('hidden');
        if (onConfirm) onConfirm();
    };

    cancelBtn.onclick = () => {
        modal.classList.add('hidden');
        if (onCancel) onCancel();
    };
}

function showPrompt(message, defaultValue, onSubmit) {
    const value = prompt(message, defaultValue);
    if (value !== null && onSubmit) {
        onSubmit(value);
    }
    return value;
}

// --- UI Logic ---

function showDashboard() {
    authView.classList.add("hidden");
    dashboardView.classList.remove("hidden");
    document.getElementById("current-user").innerText = currentUser;
    currentFolderId = null; // Reset to root on load
    loadFiles();
}

function switchTab(tab) {
    // Reset styles
    [tabFiles, tabShared, tabManage, tabSecurity].forEach(t => {
        if (t) {
            t.classList.remove("text-blue-600", "border-b-2", "border-blue-600");
            t.classList.add("text-gray-500");
        }
    });

    // Get viewAdmin element
    const viewAdmin = document.getElementById("view-admin");

    // Hide all views including admin
    [viewFiles, viewShared, viewManage, viewSecurity, viewAdmin].forEach(v => {
        if (v) v.classList.add("hidden");
    });

    // Activate selected
    if (tab === 'files') {
        tabFiles.classList.add("text-blue-600", "border-b-2", "border-blue-600");
        tabFiles.classList.remove("text-gray-500");
        viewFiles.classList.remove("hidden");
        loadFiles();
    } else if (tab === 'shared') {
        tabShared.classList.add("text-blue-600", "border-b-2", "border-blue-600");
        tabShared.classList.remove("text-gray-500");
        viewShared.classList.remove("hidden");
        loadFiles(); // loadFiles fetches both, we just show different view
    } else if (tab === 'manage') {
        tabManage.classList.add("text-blue-600", "border-b-2", "border-blue-600");
        tabManage.classList.remove("text-gray-500");
        viewManage.classList.remove("hidden");
        loadManagedShares();
    } else if (tab === 'security') {
        tabSecurity.classList.add("text-blue-600", "border-b-2", "border-blue-600");
        tabSecurity.classList.remove("text-gray-500");
        viewSecurity.classList.remove("hidden");
        loadSecurityStatus();
    }
}

// --- Persistence (IndexedDB) ---
const DB_NAME = "SecureVaultDB";
const DB_VERSION = 1;

function openDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains("keys")) {
                db.createObjectStore("keys", { keyPath: "id" });
            }
        };
        req.onsuccess = (e) => resolve(e.target.result);
        req.onerror = (e) => reject(e);
    });
}

async function saveKeys(username, signKeys, encKeys, isAdmin = false) {
    const db = await openDB();
    const tx = db.transaction("keys", "readwrite");
    const store = tx.objectStore("keys");
    store.put({
        id: "current_user",
        username: username,
        token: authToken, // Persist token
        signingKeyPair: signKeys,
        encryptionKeyPair: encKeys,
        isAdmin: isAdmin
    });
    return new Promise((resolve) => { tx.oncomplete = () => resolve(); });
}

async function loadKeys() {
    const db = await openDB();
    const tx = db.transaction("keys", "readonly");
    const store = tx.objectStore("keys");
    const req = store.get("current_user");
    return new Promise((resolve) => {
        req.onsuccess = () => resolve(req.result);
    });
}

async function clearKeys() {
    const db = await openDB();
    const tx = db.transaction("keys", "readwrite");
    const store = tx.objectStore("keys");
    store.delete("current_user");
    return new Promise((resolve) => { tx.oncomplete = () => resolve(); });
}

// Check for existing session on load
window.onload = async () => {
    // Check for Public Link
    const urlParams = new URLSearchParams(window.location.search);
    const publicToken = urlParams.get('public_token');

    if (publicToken) {
        handlePublicLink(publicToken);
        return;
    }

    const session = await loadKeys();
    if (session) {
        currentUser = session.username;
        authToken = session.token;
        signingKeyPair = session.signingKeyPair;
        encryptionKeyPair = session.encryptionKeyPair;
        usernameInput.value = currentUser;

        if (session.isAdmin) {
            document.getElementById("btn-admin").classList.remove("hidden");
        }

        // If we have a token, we might be logged in. 
        // Ideally we should verify it, but for now let's assume valid if present.
        if (authToken) {
            showDashboard();
        } else {
            login();
        }
    }
};

// --- Folder Logic ---

// Show/Hide Modal
if (btnCreateFolder) {
    btnCreateFolder.onclick = () => {
        modalCreateFolder.classList.remove("hidden");
        // We need to use a timeout because the modal is hidden
        // and focus won't work immediately
        setTimeout(() => inputFolderName.focus(), 50);
    };
}

if (btnFolderCancel) {
    btnFolderCancel.onclick = () => {
        modalCreateFolder.classList.add("hidden");
        inputFolderName.value = "";
    };
}

// Create Folder API Call
if (btnFolderCreate) {
    btnFolderCreate.onclick = async () => {
        const name = inputFolderName.value.trim();
        if (!name) return alert("Please enter a folder name");

        try {
            const res = await fetch(`${API_URL}/folders`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${authToken}`
                },
                body: JSON.stringify({
                    name: name,
                    parent_id: currentFolderId
                })
            });

            const data = await res.json();
            if (data.ok) {
                showToast("Folder created!", 'success');
                modalCreateFolder.classList.add("hidden");
                inputFolderName.value = "";
                loadFiles();
            } else {
                showToast("Error: " + data.msg, 'error');
            }
        } catch (e) {
            console.error(e);
            showToast("Error creating folder", 'error');
        }
    };
}

// Navigation
function navigateFolder(folderId) {
    currentFolderId = folderId;
    loadFiles();
}

function renderBreadcrumbs(crumbs) {
    if (!breadcrumbsContainer) return;

    // Reset to just Home
    breadcrumbsContainer.innerHTML = '';

    // Home Link
    const homeSpan = document.createElement("span");
    homeSpan.className = "hover:text-blue-400 cursor-pointer transition-colors";
    homeSpan.textContent = "Home";
    homeSpan.onclick = () => navigateFolder(null); // Navigate to root
    breadcrumbsContainer.appendChild(homeSpan);

    if (crumbs && crumbs.length > 0) {
        // Separator and Crumbs
        crumbs.forEach(c => {
            const sep = document.createElement("span");
            sep.className = "text-slate-600";
            sep.textContent = "/";
            breadcrumbsContainer.appendChild(sep);

            const span = document.createElement("span");
            span.className = "hover:text-blue-400 cursor-pointer transition-colors";
            span.textContent = c.name;
            span.onclick = () => navigateFolder(c.id);
            breadcrumbsContainer.appendChild(span);
        });
    }
}

// --- Crypto Utils ---

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

async function generateSigningKeys() {
    return window.crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    );
}

async function generateEncryptionKeys() {
    return window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function exportKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    const b64 = arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

async function signChallenge(privateKey, challengeB64) {
    const challenge = base64ToArrayBuffer(challengeB64);
    const signature = await window.crypto.subtle.sign(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        privateKey,
        challenge
    );
    return arrayBufferToBase64(signature);
}

// --- File Encryption Utils ---

async function encryptFile(file, recipientPublicKey) {
    // 1. Generate random AES-GCM key
    const fileKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    // 2. Encrypt file content
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const fileBuffer = await file.arrayBuffer();
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        fileKey,
        fileBuffer
    );

    // 3. Encrypt AES key with Recipient's RSA Public Key
    // We need to export AES key to raw bytes first to encrypt it
    const rawFileKey = await window.crypto.subtle.exportKey("raw", fileKey);
    const encryptedKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPublicKey,
        rawFileKey
    );

    return {
        encryptedContent: encryptedContent,
        encryptedKey: arrayBufferToBase64(encryptedKey),
        iv: arrayBufferToBase64(iv)
    };
}

async function decryptFile(encryptedContent, encryptedKeyB64, ivB64, privateKey) {
    // 1. Decrypt AES Key
    const encryptedKey = base64ToArrayBuffer(encryptedKeyB64);
    const rawFileKey = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedKey
    );

    // Import AES Key
    const fileKey = await window.crypto.subtle.importKey(
        "raw",
        rawFileKey,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"]
    );

    // 2. Decrypt Content
    const iv = base64ToArrayBuffer(ivB64);
    const decryptedContent = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        fileKey,
        encryptedContent
    );

    return decryptedContent;
}

// --- Auth Logic ---

async function register() {
    const username = usernameInput.value;
    if (!username) return alert("Enter username");

    // Capability Check
    if (!window.crypto || !window.crypto.subtle) {
        authStatus.innerText = "Error: Web Crypto API not supported in this browser or context (requires HTTPS or localhost).";
        return;
    }

    authStatus.innerText = "Generating keys...";

    try {
        signingKeyPair = await generateSigningKeys();
        encryptionKeyPair = await generateEncryptionKeys();

        const signPubPem = await exportKey(signingKeyPair.publicKey);
        const encPubPem = await exportKey(encryptionKeyPair.publicKey);

        // Save keys to IndexedDB
        await saveKeys(username, signingKeyPair, encryptionKeyPair);

        const res = await fetch(`${API_URL}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username,
                public_key_pem: signPubPem,
                encryption_public_key_pem: encPubPem
            })
        });

        const data = await res.json();
        if (data.ok) {
            authStatus.innerText = "Registered! Logging in...";
            await login();
        } else {
            authStatus.innerText = "Error: " + data.msg;
        }
    } catch (e) {
        console.error("Registration Error:", e);
        authStatus.innerText = "Error generating keys: " + e.message;
    }
}

async function login() {
    const username = usernameInput.value;
    if (!username) return alert("Enter username");

    if (!signingKeyPair) {
        return alert("Keys not found in memory. Please Register (Persistence not implemented in this demo).");
    }

    // 1. Get Challenge
    const res = await fetch(`${API_URL}/challenge/${username}`);
    const data = await res.json();
    if (!data.ok) return alert(data.msg);

    // 2. Sign Challenge
    const signature = await signChallenge(signingKeyPair.privateKey, data.challenge);

    // 3. Verify
    const res2 = await fetch(`${API_URL}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            challenge: data.challenge,
            signature
        })
    });

    const data2 = await res2.json();
    if (data2.ok) {
        currentUser = username;
        authToken = data2.token;

        if (data2.is_admin) {
            document.getElementById("btn-admin").classList.remove("hidden");
        } else {
            document.getElementById("btn-admin").classList.add("hidden");
        }

        // Update persistence with token
        await saveKeys(currentUser, signingKeyPair, encryptionKeyPair, data2.is_admin);
        showDashboard();
        showToast("Login successful!", 'success');

        // Show 2FA reminder if not enabled (optional)
        if (!data2.twofa_enabled) {
            setTimeout(() => {
                const reminderModal = document.getElementById("2fa-reminder-modal");
                if (reminderModal) {
                    reminderModal.classList.remove("hidden");
                }
            }, 2000);
        }
    } else if (data2.msg === "2FA required") {
        // Show 2FA modal
        const modal = document.getElementById("2fa-input-modal");
        const codeInput = document.getElementById("login-2fa-code");
        modal.classList.remove("hidden");
        codeInput.value = "";
        codeInput.focus();

        // Store challenge and signature for 2FA verification
        window.pendingLogin = {
            username,
            challenge: data.challenge,
            signature
        };
    } else {
        showToast("Login failed: " + data2.msg, 'error');
    }
}

// --- File Logic ---

async function handleFileUpload(file) {
    if (!currentUser || !encryptionKeyPair) return;

    uploadProgress.classList.remove("hidden");
    uploadProgress.innerText = "Encrypting...";

    try {
        // Encrypt for SELF (using own public key)
        const result = await encryptFile(file, encryptionKeyPair.publicKey);

        uploadProgress.innerText = "Uploading...";

        const formData = new FormData();
        // formData.append("username", currentUser); // No longer needed
        formData.append("file", new File([result.encryptedContent], file.name));
        formData.append("encrypted_key", result.encryptedKey);
        formData.append("encrypted_key", result.encryptedKey);
        formData.append("iv", result.iv);
        formData.append("parent_id", currentFolderId); // Add parent folder context

        const res = await fetch(`${API_URL}/upload`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${authToken}` },
            body: formData
        });

        const data = await res.json();
        if (data.ok) {
            uploadProgress.innerText = "Upload Complete!";
            loadFiles();
            setTimeout(() => uploadProgress.classList.add("hidden"), 2000);
        } else {
            uploadProgress.innerText = "Error: " + data.msg;
        }
    } catch (e) {
        console.error("Encryption/Upload Error:", e);
        uploadProgress.innerText = "Encryption Failed! " + e.message;
    }
}

// --- Sharing & Preview Logic ---

async function loadFiles() {
    const res = await fetch(`${API_URL}/files?parent_id=${currentFolderId}`, {
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    const data = await res.json();
    if (data.ok) {
        // Update quota display
        await loadQuota();

        // Update Breadcrumbs
        renderBreadcrumbs(data.breadcrumbs);

        // My Files
        fileList.innerHTML = "";
        if (data.files.length === 0) {
            fileList.innerHTML = '<li class="text-gray-500 italic text-center py-8">Folder is empty. Upload or create a subfolder!</li>';
        } else {
            data.files.forEach(f => {
                const li = document.createElement("li");
                li.className = "flex justify-between items-center bg-slate-800 p-4 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors group";
                
                // Set attributes for drag and drop
                if (f.is_folder) {
                    li.setAttribute("data-folder-id", f.id);
                    li.setAttribute("data-is-folder", "true");
                } else {
                    li.setAttribute("data-file-id", f.id);
                    li.setAttribute("draggable", "true");
                }

                const infoDiv = document.createElement("div");
                infoDiv.className = "flex-1 flex items-center gap-3 cursor-pointer";

                // Icon Logic
                let icon = '';
                if (f.is_folder) {
                    icon = `<svg class="w-8 h-8 text-blue-400" fill="currentColor" viewBox="0 0 20 20"><path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z"></path></svg>`;
                    infoDiv.onclick = () => navigateFolder(f.id); // Click to enter folder
                } else {
                    icon = `<svg class="w-8 h-8 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>`;
                    infoDiv.onclick = () => previewFile(f.id); // Click to preview file
                }

                const textDiv = document.createElement("div");
                const nameDiv = document.createElement("div");
                nameDiv.className = "font-medium text-white mb-1 group-hover:text-blue-400 transition-colors";
                nameDiv.textContent = f.filename;

                const metaDiv = document.createElement("div");
                metaDiv.className = "text-xs text-gray-400";

                if (f.is_folder) {
                    metaDiv.textContent = `Folder • ${new Date(f.created_at).toLocaleDateString()}`;
                } else {
                    metaDiv.textContent = `${formatBytes(f.file_size)} • ${new Date(f.created_at).toLocaleDateString()}`;
                }

                textDiv.appendChild(nameDiv);
                textDiv.appendChild(metaDiv);

                infoDiv.innerHTML = icon;
                infoDiv.appendChild(textDiv);

                // Hamburger menu button
                const menuBtn = document.createElement("button");
                menuBtn.className = "p-2 text-gray-400 hover:text-white hover:bg-slate-700 rounded transition-colors";
                menuBtn.innerHTML = `
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path>
                    </svg>
                `;
                
                // Dropdown menu
                const dropdownMenu = document.createElement("div");
                dropdownMenu.className = "hidden absolute right-0 mt-2 w-48 bg-slate-800 rounded-lg shadow-xl border border-slate-700 z-50";
                dropdownMenu.setAttribute("data-menu-id", f.id);
                
                const menuItems = document.createElement("div");
                menuItems.className = "py-1";
                
                // Show actions for files
                if (!f.is_folder) {
                    // Open
                    const openItem = createMenuItem("Open", "text-blue-400 hover:bg-blue-500/10", () => {
                        dropdownMenu.classList.add("hidden");
                        previewFile(f.id);
                    });
                    menuItems.appendChild(openItem);
                    
                    // Rename
                    const renameItem = createMenuItem("Rename", "text-blue-400 hover:bg-blue-500/10", () => {
                        dropdownMenu.classList.add("hidden");
                        renameFile(f.id, f.filename);
                    });
                    menuItems.appendChild(renameItem);
                    
                    // Share
                    const shareItem = createMenuItem("Share", "text-green-400 hover:bg-green-500/10", () => {
                        dropdownMenu.classList.add("hidden");
                        shareFile(f.id, f.filename);
                    });
                    menuItems.appendChild(shareItem);
                    
                    // Link
                    const linkItem = createMenuItem("Create Public Link", "text-purple-400 hover:bg-purple-500/10", () => {
                        dropdownMenu.classList.add("hidden");
                        createPublicLink(f.id, f.filename);
                    });
                    menuItems.appendChild(linkItem);
                    
                    // Move
                    const moveItem = createMenuItem("Move to Folder", "text-yellow-400 hover:bg-yellow-500/10", () => {
                        dropdownMenu.classList.add("hidden");
                        showMoveFileModal(f.id, f.filename);
                    });
                    menuItems.appendChild(moveItem);
                    
                    const separator = document.createElement("hr");
                    separator.className = "border-slate-700 my-1";
                    menuItems.appendChild(separator);
                } else {
                    // Show actions for folders
                    // Rename
                    const renameItem = createMenuItem("Rename", "text-blue-400 hover:bg-blue-500/10", () => {
                        console.log("Rename menu item clicked");
                        dropdownMenu.classList.add("hidden");
                        renameFolder(f.id, f.filename);
                    });
                    menuItems.appendChild(renameItem);
                    
                    // Share Folder
                    const shareFolderItem = createMenuItem("Share Folder", "text-green-400 hover:bg-green-500/10", () => {
                        console.log("Share folder menu item clicked");
                        dropdownMenu.classList.add("hidden");
                        shareFolder(f.id, f.filename);
                    });
                    menuItems.appendChild(shareFolderItem);
                    
                    // Move
                    const moveItem = createMenuItem("Move to Folder", "text-yellow-400 hover:bg-yellow-500/10", () => {
                        dropdownMenu.classList.add("hidden");
                        showMoveFileModal(f.id, f.filename);
                    });
                    menuItems.appendChild(moveItem);
                    
                    const separator = document.createElement("hr");
                    separator.className = "border-slate-700 my-1";
                    menuItems.appendChild(separator);
                }
                
                // Delete
                const deleteItem = createMenuItem("Delete", "text-red-400 hover:bg-red-500/10", () => {
                    dropdownMenu.classList.add("hidden");
                    deleteFile(f.id);
                });
                menuItems.appendChild(deleteItem);
                
                dropdownMenu.appendChild(menuItems);
                
                // Toggle dropdown on click
                menuBtn.onclick = (e) => {
                    e.stopPropagation();
                    // Close all other dropdowns
                    document.querySelectorAll('[data-menu-id]').forEach(menu => {
                        if (menu !== dropdownMenu) {
                            menu.classList.add("hidden");
                        }
                    });
                    dropdownMenu.classList.toggle("hidden");
                };
                
                const menuContainer = document.createElement("div");
                menuContainer.className = "relative";
                menuContainer.appendChild(menuBtn);
                menuContainer.appendChild(dropdownMenu);

                li.appendChild(infoDiv);
                li.appendChild(menuContainer);
                fileList.appendChild(li);
            });
        }
        
        // Setup drag and drop for files
        setupFileDragAndDrop();
        
        // Close dropdowns when clicking outside (only add once)
        if (!window.dropdownCloseHandlerAdded) {
            document.addEventListener('click', (e) => {
                // Check if click is outside any menu container
                const clickedMenuBtn = e.target.closest('button[class*="p-2"]');
                const clickedMenu = e.target.closest('[data-menu-id]');
                
                if (!clickedMenuBtn && !clickedMenu) {
                    document.querySelectorAll('[data-menu-id]').forEach(menu => {
                        menu.classList.add("hidden");
                    });
                }
            });
            window.dropdownCloseHandlerAdded = true;
        }

        // Shared With Me
        const sharedList = document.getElementById("shared-list");
        if (sharedList) {
            sharedList.innerHTML = "";
            if (data.shared.length === 0) {
                sharedList.innerHTML = '<li class="text-gray-500 italic text-center py-8">No shared files</li>';
            } else {
                data.shared.forEach(f => {
                    const li = document.createElement("li");
                    li.className = "flex justify-between items-center bg-slate-800 p-4 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors";

                    const infoDiv = document.createElement("div");
                    infoDiv.className = "flex-1";

                    const nameDiv = document.createElement("div");
                    nameDiv.className = "font-medium text-white mb-1";
                    nameDiv.textContent = f.filename;

                    const metaDiv = document.createElement("div");
                    metaDiv.className = "text-xs text-gray-400";
                    metaDiv.textContent = `From ${f.owner} • ${formatBytes(f.file_size)} • ${new Date(f.created_at).toLocaleDateString()}`;

                    infoDiv.appendChild(nameDiv);
                    infoDiv.appendChild(metaDiv);

                    const openBtn = document.createElement("button");
                    openBtn.className = "px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors";
                    openBtn.textContent = "Open";
                    openBtn.onclick = () => previewFile(f.id, f.owner);

                    li.appendChild(infoDiv);
                    li.appendChild(openBtn);
                    sharedList.appendChild(li);
                });
            }
        }
    }
}

async function loadQuota() {
    const res = await fetch(`${API_URL}/quota`, {
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    const data = await res.json();
    if (data.ok) {
        const quotaText = document.getElementById("quota-text");
        const quotaBar = document.getElementById("quota-bar");
        quotaText.textContent = `${formatBytes(data.used)} / ${formatBytes(data.quota)}`;
        quotaBar.style.width = `${data.percentage}%`;

        if (data.percentage > 90) {
            quotaBar.classList.remove("bg-blue-500");
            quotaBar.classList.add("bg-red-500");
        } else if (data.percentage > 75) {
            quotaBar.classList.remove("bg-blue-500");
            quotaBar.classList.add("bg-yellow-500");
        }
    }
}

async function deleteFile(fileId) {
    if (!confirm("Are you sure you want to delete this file? This action cannot be undone.")) return;

    const res = await fetch(`${API_URL}/files/${fileId}`, {
        method: 'DELETE',
        headers: { "Authorization": `Bearer ${authToken}` }
    });

    const data = await res.json();
    if (data.ok) {
        alert("File deleted successfully!");
        loadFiles();
    } else {
        alert("Error: " + data.msg);
    }
}

async function loadManagedShares() {
    const res = await fetch(`${API_URL}/shares/manage`, {
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    const data = await res.json();

    if (data.ok) {
        const publicList = document.getElementById("manage-public-list");
        const userList = document.getElementById("manage-user-list");

        publicList.innerHTML = "";
        data.public_links.forEach(l => {
            // Force UTC interpretation
            const utcString = l.expires_at.endsWith('Z') ? l.expires_at : l.expires_at + 'Z';
            const expiryDate = new Date(utcString);
            const isExpired = new Date() > expiryDate;

            const li = document.createElement("li");
            li.className = "flex justify-between items-center bg-slate-800 p-3 rounded border border-slate-700";

            const infoDiv = document.createElement("div");

            const nameDiv = document.createElement("div");
            nameDiv.className = "font-bold text-white";
            nameDiv.textContent = l.filename;

            const expiryDiv = document.createElement("div");
            expiryDiv.className = `text-xs ${isExpired ? "text-red-500" : "text-gray-400"}`;
            expiryDiv.textContent = `Expires: ${expiryDate.toLocaleString()}`;

            const accessDiv = document.createElement("div");
            accessDiv.className = "text-xs text-gray-500";
            accessDiv.textContent = `Access: ${l.access_count} ${l.max_access ? '/ ' + l.max_access : ''}`;

            infoDiv.appendChild(nameDiv);
            infoDiv.appendChild(expiryDiv);
            infoDiv.appendChild(accessDiv);

            const btnDiv = document.createElement("div");
            btnDiv.className = "flex gap-2";

            const copyBtn = document.createElement("button");
            copyBtn.className = "text-blue-400 hover:text-blue-300 text-sm font-medium";
            copyBtn.textContent = "Copy Link";
            copyBtn.onclick = () => copyPublicLink(l.token, l.file_id);

            const revokeBtn = document.createElement("button");
            revokeBtn.className = "text-red-400 hover:text-red-300 text-sm font-medium";
            revokeBtn.textContent = "Revoke";
            revokeBtn.onclick = () => revokePublicShare(l.token);

            btnDiv.appendChild(copyBtn);
            btnDiv.appendChild(revokeBtn);

            li.appendChild(infoDiv);
            li.appendChild(btnDiv);
            publicList.appendChild(li);
        });

        userList.innerHTML = "";
        data.user_shares.forEach(s => {
            const li = document.createElement("li");
            li.className = "flex justify-between items-center bg-slate-800 p-3 rounded border border-slate-700";

            const infoDiv = document.createElement("div");

            const nameDiv = document.createElement("div");
            nameDiv.className = "font-bold text-white";
            nameDiv.textContent = s.filename;

            const shareDiv = document.createElement("div");
            shareDiv.className = "text-xs text-gray-400";
            shareDiv.innerHTML = `Shared with: <span class="text-blue-400">${s.recipient}</span>`; // Safe as recipient is username
            // Better safe:
            shareDiv.innerHTML = "";
            shareDiv.appendChild(document.createTextNode("Shared with: "));
            const span = document.createElement("span");
            span.className = "text-blue-400";
            span.textContent = s.recipient;
            shareDiv.appendChild(span);

            const dateDiv = document.createElement("div");
            dateDiv.className = "text-xs text-gray-500";
            dateDiv.textContent = `Date: ${new Date(s.created_at + 'Z').toLocaleString()}`;

            infoDiv.appendChild(nameDiv);
            infoDiv.appendChild(shareDiv);
            infoDiv.appendChild(dateDiv);

            const revokeBtn = document.createElement("button");
            revokeBtn.className = "text-red-400 hover:text-red-300 text-sm font-medium";
            revokeBtn.textContent = "Revoke";
            revokeBtn.onclick = () => revokeUserShare(s.id);

            li.appendChild(infoDiv);
            li.appendChild(revokeBtn);
            userList.appendChild(li);
        });

        if (data.public_links.length === 0) publicList.innerHTML = "<li class='text-gray-500 italic'>No active public links</li>";
        if (data.user_shares.length === 0) userList.innerHTML = "<li class='text-gray-500 italic'>No active user shares</li>";
    }
}

async function copyPublicLink(token, fileId) {
    try {
        // 1. Get File Key (Encrypted for ME)
        const resFile = await fetch(`${API_URL}/download/${fileId}`, {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const dataFile = await resFile.json();
        if (!dataFile.ok) return alert("Failed to fetch file info to reconstruct link");

        // 2. Decrypt File Key
        const encryptedKey = base64ToArrayBuffer(dataFile.encrypted_key);
        const rawFileKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            encryptionKeyPair.privateKey,
            encryptedKey
        );

        // 3. Export Raw File Key to Base64
        const fileKeyB64 = arrayBufferToBase64(rawFileKey);

        // 4. Construct Link
        const link = `${window.location.origin}/?public_token=${token}#key=${encodeURIComponent(fileKeyB64)}`;

        // 5. Copy to Clipboard
        await navigator.clipboard.writeText(link);
        alert("Link copied to clipboard!");

    } catch (e) {
        console.error(e);
        alert("Failed to copy link: " + e.message);
    }
}

async function revokePublicShare(token) {
    if (!confirm("Revoke this public link? It will stop working immediately.")) return;
    const res = await fetch(`${API_URL}/share/public/${token}`, {
        method: 'DELETE',
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    if (res.ok) loadManagedShares();
}

async function revokeUserShare(id) {
    if (!confirm("Revoke access for this user?")) return;
    const res = await fetch(`${API_URL}/share/user/${id}`, {
        method: 'DELETE',
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    if (res.ok) loadManagedShares();
}

// Share file function
let currentShareFileId = null;
function showShareFileModal(fileId, fileName) {
    currentShareFileId = fileId;
    const modal = document.getElementById("share-file-modal");
    const nameEl = document.getElementById("share-file-name");
    const usernameInput = document.getElementById("share-file-username");
    
    nameEl.textContent = `Sharing file: ${fileName}`;
    usernameInput.value = "";
    modal.classList.remove("hidden");
    setTimeout(() => usernameInput.focus(), 50);
}

async function shareFile(fileId, fileName) {
    showShareFileModal(fileId, fileName);
}

async function confirmShareFile() {
    if (!currentShareFileId) return;
    
    const usernameInput = document.getElementById("share-file-username");
    const recipient = usernameInput.value.trim();
    
    if (!recipient) {
        showToast("Please enter a username", 'error');
        return;
    }

    try {
        // 1. Get Recipient Public Key
        const resKey = await fetch(`${API_URL}/keys/${recipient}`);
        const dataKey = await resKey.json();
        if (!dataKey.ok) {
            showToast("User not found or has no keys", 'error');
            return;
        }

        const recipientPubKey = await window.crypto.subtle.importKey(
            "spki",
            base64ToArrayBuffer(dataKey.encryption_public_key_pem.replace(/-----BEGIN PUBLIC KEY-----|\n|-----END PUBLIC KEY-----/g, "")),
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );

        // 2. Get File Key (Encrypted for ME)
        const resFile = await fetch(`${API_URL}/download/${currentShareFileId}`, {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const dataFile = await resFile.json();
        if (!dataFile.ok) {
            showToast("Failed to fetch file info", 'error');
            return;
        }

        // 3. Decrypt File Key with MY Private Key
        const encryptedKey = base64ToArrayBuffer(dataFile.encrypted_key);
        const rawFileKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            encryptionKeyPair.privateKey,
            encryptedKey
        );

        // 4. Encrypt File Key with RECIPIENT Public Key
        const newEncryptedKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            recipientPubKey,
            rawFileKey
        );

        // 5. Send to Server
        const resShare = await fetch(`${API_URL}/share`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                file_id: currentShareFileId,
                recipient_username: recipient,
                encrypted_key: arrayBufferToBase64(newEncryptedKey)
            })
        });

        const dataShare = await resShare.json();
        if (dataShare.ok) {
            showToast(`Successfully shared with ${recipient}!`, 'success');
            document.getElementById("share-file-modal").classList.add("hidden");
            currentShareFileId = null;
        } else {
            showToast("Share failed: " + dataShare.msg, 'error');
        }

    } catch (e) {
        console.error(e);
        showToast("Sharing failed: " + e.message, 'error');
    }
}

// Share folder function
let currentShareFolderId = null;
function showShareFolderModal(folderId, folderName) {
    currentShareFolderId = folderId;
    const modal = document.getElementById("share-folder-modal");
    const nameEl = document.getElementById("share-folder-name");
    const usernameInput = document.getElementById("share-folder-username");
    
    nameEl.textContent = `Sharing folder: ${folderName}`;
    usernameInput.value = "";
    modal.classList.remove("hidden");
    setTimeout(() => usernameInput.focus(), 50);
}

async function shareFolder(folderId, folderName) {
    showShareFolderModal(folderId, folderName);
}

async function confirmShareFolder() {
    if (!currentShareFolderId) return;
    
    const usernameInput = document.getElementById("share-folder-username");
    const recipient = usernameInput.value.trim();
    
    if (!recipient) {
        showToast("Please enter a username", 'error');
        return;
    }

    try {
        const resShare = await fetch(`${API_URL}/share`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                file_id: currentShareFolderId,
                recipient_username: recipient
            })
        });

        const dataShare = await resShare.json();
        if (dataShare.ok) {
            showToast(`Folder shared with ${recipient}! ${dataShare.msg || ''}`, 'success');
            document.getElementById("share-folder-modal").classList.add("hidden");
            currentShareFolderId = null;
        } else {
            showToast("Share failed: " + dataShare.msg, 'error');
        }

    } catch (e) {
        console.error("Share folder error:", e);
        showToast("Sharing failed: " + e.message, 'error');
    }
}

// Rename folder function
let currentRenameFolderId = null;
function showRenameFolderModal(folderId, currentName) {
    currentRenameFolderId = folderId;
    const modal = document.getElementById("rename-folder-modal");
    const nameEl = document.getElementById("rename-folder-current-name");
    const nameInput = document.getElementById("rename-folder-input");
    
    nameEl.textContent = `Current name: ${currentName}`;
    nameInput.value = currentName;
    modal.classList.remove("hidden");
    setTimeout(() => {
        nameInput.focus();
        nameInput.select();
    }, 50);
}

async function renameFolder(folderId, currentName) {
    showRenameFolderModal(folderId, currentName);
}

async function confirmRenameFolder() {
    if (!currentRenameFolderId) return;
    
    const nameInput = document.getElementById("rename-folder-input");
    const newName = nameInput.value.trim();
    
    if (!newName) {
        showToast("Please enter a folder name", 'error');
        return;
    }

    try {
        const res = await fetch(`${API_URL}/files/${currentRenameFolderId}/rename`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                name: newName
            })
        });

        const data = await res.json();
        if (data.ok) {
            showToast("Folder renamed successfully!", 'success');
            document.getElementById("rename-folder-modal").classList.add("hidden");
            currentRenameFolderId = null;
            loadFiles();
        } else {
            showToast("Error: " + data.msg, 'error');
        }
    } catch (e) {
        console.error("Rename folder error:", e);
        showToast("Failed to rename folder", 'error');
    }
}

// Modal event handlers
const btnRenameCancel = document.getElementById("btn-rename-cancel");
const btnRenameConfirm = document.getElementById("btn-rename-confirm");
const btnShareFolderCancel = document.getElementById("btn-share-folder-cancel");
const btnShareFolderConfirm = document.getElementById("btn-share-folder-confirm");
const btnShareFileCancel = document.getElementById("btn-share-file-cancel");
const btnShareFileConfirm = document.getElementById("btn-share-file-confirm");
const btnPublicLinkCancel = document.getElementById("btn-public-link-cancel");
const btnPublicLinkCreate = document.getElementById("btn-public-link-create");
const btnRenameFileCancel = document.getElementById("btn-rename-file-cancel");
const btnRenameFileConfirm = document.getElementById("btn-rename-file-confirm");
const btnCopyLink = document.getElementById("btn-copy-link");

// Rename folder handlers
if (btnRenameCancel) {
    btnRenameCancel.onclick = () => {
        document.getElementById("rename-folder-modal").classList.add("hidden");
        currentRenameFolderId = null;
    };
}

if (btnRenameConfirm) {
    btnRenameConfirm.onclick = confirmRenameFolder;
}

// Share folder handlers
if (btnShareFolderCancel) {
    btnShareFolderCancel.onclick = () => {
        document.getElementById("share-folder-modal").classList.add("hidden");
        currentShareFolderId = null;
    };
}

if (btnShareFolderConfirm) {
    btnShareFolderConfirm.onclick = confirmShareFolder;
}

// Share file handlers
if (btnShareFileCancel) {
    btnShareFileCancel.onclick = () => {
        document.getElementById("share-file-modal").classList.add("hidden");
        currentShareFileId = null;
    };
}

if (btnShareFileConfirm) {
    btnShareFileConfirm.onclick = confirmShareFile;
}

// Public link handlers
if (btnPublicLinkCancel) {
    btnPublicLinkCancel.onclick = () => {
        document.getElementById("public-link-modal").classList.add("hidden");
        currentPublicLinkFileId = null;
    };
}

if (btnPublicLinkCreate) {
    btnPublicLinkCreate.onclick = confirmCreatePublicLink;
}

if (btnCopyLink) {
    btnCopyLink.onclick = () => {
        const linkInput = document.getElementById("public-link-url");
        linkInput.select();
        navigator.clipboard.writeText(linkInput.value).then(() => {
            showToast("Link copied to clipboard!", 'success');
        }).catch(() => {
            showToast("Failed to copy link", 'error');
        });
    };
}

// Rename file handlers
if (btnRenameFileCancel) {
    btnRenameFileCancel.onclick = () => {
        document.getElementById("rename-file-modal").classList.add("hidden");
        currentRenameFileId = null;
    };
}

if (btnRenameFileConfirm) {
    btnRenameFileConfirm.onclick = confirmRenameFile;
}

// Allow Enter key to submit
if (document.getElementById("rename-folder-input")) {
    document.getElementById("rename-folder-input").addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            confirmRenameFolder();
        }
    });
}

if (document.getElementById("share-folder-username")) {
    document.getElementById("share-folder-username").addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            confirmShareFolder();
        }
    });
}

if (document.getElementById("share-file-username")) {
    document.getElementById("share-file-username").addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            confirmShareFile();
        }
    });
}

if (document.getElementById("public-link-duration")) {
    document.getElementById("public-link-duration").addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            confirmCreatePublicLink();
        }
    });
}

if (document.getElementById("rename-file-input")) {
    document.getElementById("rename-file-input").addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            confirmRenameFile();
        }
    });
}

// Create public link function
let currentPublicLinkFileId = null;
function showPublicLinkModal(fileId, fileName) {
    currentPublicLinkFileId = fileId;
    const modal = document.getElementById("public-link-modal");
    const nameEl = document.getElementById("public-link-file-name");
    const durationInput = document.getElementById("public-link-duration");
    const oneTimeCheckbox = document.getElementById("public-link-one-time");
    const resultDiv = document.getElementById("public-link-result");
    const linkInput = document.getElementById("public-link-url");
    
    nameEl.textContent = `Creating public link for: ${fileName}`;
    durationInput.value = "1";
    oneTimeCheckbox.checked = false;
    resultDiv.classList.add("hidden");
    linkInput.value = "";
    modal.classList.remove("hidden");
    setTimeout(() => durationInput.focus(), 50);
}

async function createPublicLink(fileId, fileName) {
    showPublicLinkModal(fileId, fileName);
}

async function confirmCreatePublicLink() {
    if (!currentPublicLinkFileId) return;
    
    const durationInput = document.getElementById("public-link-duration");
    const oneTimeCheckbox = document.getElementById("public-link-one-time");
    const duration = durationInput.value;
    
    if (!duration || parseInt(duration) < 1) {
        showToast("Please enter a valid duration (at least 1 hour)", 'error');
        return;
    }

    const oneTime = oneTimeCheckbox.checked;

    try {
        // 1. Get File Key (Encrypted for ME)
        const resFile = await fetch(`${API_URL}/download/${currentPublicLinkFileId}`, {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const dataFile = await resFile.json();
        if (!dataFile.ok) {
            showToast("Failed to fetch file info", 'error');
            return;
        }

        // 2. Decrypt File Key
        const encryptedKey = base64ToArrayBuffer(dataFile.encrypted_key);
        const rawFileKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            encryptionKeyPair.privateKey,
            encryptedKey
        );

        // 3. Export Raw File Key to Base64 (to put in URL hash)
        const fileKeyB64 = arrayBufferToBase64(rawFileKey);

        // 4. Request Public Token from Server
        const resLink = await fetch(`${API_URL}/share/public`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                file_id: currentPublicLinkFileId,
                duration_hours: parseInt(duration),
                max_access: oneTime ? 1 : null
            })
        });

        const dataLink = await resLink.json();
        if (dataLink.ok) {
            // URL Encode the key to preserve '+' characters
            const link = `${window.location.origin}/?public_token=${dataLink.token}#key=${encodeURIComponent(fileKeyB64)}`;
            const resultDiv = document.getElementById("public-link-result");
            const linkInput = document.getElementById("public-link-url");
            linkInput.value = link;
            resultDiv.classList.remove("hidden");
            showToast("Public link created! Copy the link below.", 'success');
        } else {
            showToast("Failed to create link: " + dataLink.msg, 'error');
        }

    } catch (e) {
        console.error(e);
        showToast("Error creating public link: " + e.message, 'error');
    }
}

// Rename file function
let currentRenameFileId = null;
function showRenameFileModal(fileId, currentName) {
    currentRenameFileId = fileId;
    const modal = document.getElementById("rename-file-modal");
    const nameEl = document.getElementById("rename-file-current-name");
    const nameInput = document.getElementById("rename-file-input");
    
    nameEl.textContent = `Current name: ${currentName}`;
    nameInput.value = currentName;
    modal.classList.remove("hidden");
    setTimeout(() => {
        nameInput.focus();
        nameInput.select();
    }, 50);
}

async function renameFile(fileId, currentName) {
    showRenameFileModal(fileId, currentName);
}

async function confirmRenameFile() {
    if (!currentRenameFileId) return;
    
    const nameInput = document.getElementById("rename-file-input");
    const newName = nameInput.value.trim();
    
    if (!newName) {
        showToast("Please enter a file name", 'error');
        return;
    }

    try {
        const res = await fetch(`${API_URL}/files/${currentRenameFileId}/rename`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                name: newName
            })
        });

        const data = await res.json();
        if (data.ok) {
            showToast("File renamed successfully!", 'success');
            document.getElementById("rename-file-modal").classList.add("hidden");
            currentRenameFileId = null;
            loadFiles();
        } else {
            showToast("Error: " + data.msg, 'error');
        }
    } catch (e) {
        console.error("Rename file error:", e);
        showToast("Failed to rename file", 'error');
    }
}

async function handlePublicLink(token) {
    // Hide Auth, Show Preview directly
    authView.classList.add("hidden");

    // Parse Key from Hash
    const hash = window.location.hash.substring(1); // remove #
    const params = new URLSearchParams(hash);
    const keyB64 = params.get('key');

    if (!keyB64) {
        alert("Invalid Link: Missing Decryption Key in URL");
        return;
    }

    try {
        // Fetch Encrypted File from Server
        const res = await fetch(`${API_URL}/public/${token}`);
        const data = await res.json();

        if (!data.ok) {
            document.body.innerHTML = `<h1 style="color:white;text-align:center;margin-top:50px;">${data.msg}</h1>`;
            return;
        }

        // Import AES Key
        const rawKey = base64ToArrayBuffer(keyB64);
        const fileKey = await window.crypto.subtle.importKey(
            "raw",
            rawKey,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );

        // Decrypt
        const encryptedContent = base64ToArrayBuffer(data.file_content_b64);
        const iv = base64ToArrayBuffer(data.iv);

        const decryptedContent = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            fileKey,
            encryptedContent
        );

        // Show Preview
        const blob = new Blob([decryptedContent]);
        const url = URL.createObjectURL(blob);

        const modal = document.getElementById("preview-modal");
        const container = document.getElementById("preview-container");
        const title = document.getElementById("preview-title");

        title.innerText = data.filename;
        container.innerHTML = "";

        // Download Button
        const downloadBtn = document.createElement("button");
        downloadBtn.innerText = "Download File";
        downloadBtn.style.marginBottom = "1rem";
        downloadBtn.onclick = () => {
            const a = document.createElement("a");
            a.href = url;
            a.download = data.filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        };
        container.appendChild(downloadBtn);

        // Preview Content
        const previewContent = document.createElement("div");
        previewContent.className = "w-full";

        if (data.filename.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i)) {
            const img = document.createElement("img");
            img.src = url;
            img.className = "max-w-full max-h-[70vh] mx-auto rounded";
            previewContent.appendChild(img);
        } else if (data.filename.match(/\.(mp4|webm|ogg)$/i)) {
            const video = document.createElement("video");
            video.src = url;
            video.controls = true;
            video.className = "max-w-full max-h-[70vh] mx-auto rounded";
            previewContent.appendChild(video);
        } else if (data.filename.match(/\.(mp3|wav|ogg|m4a)$/i)) {
            const audio = document.createElement("audio");
            audio.src = url;
            audio.controls = true;
            audio.className = "w-full";
            previewContent.appendChild(audio);
        } else if (data.filename.match(/\.pdf$/i)) {
            const iframe = document.createElement("iframe");
            iframe.src = url;
            iframe.className = "w-full h-[70vh] rounded";
            previewContent.appendChild(iframe);
        } else if (data.filename.match(/\.(txt|csv|json|md|log)$/i)) {
            const pre = document.createElement("pre");
            pre.className = "bg-slate-900 p-4 rounded text-sm text-gray-300 overflow-auto max-h-[70vh]";
            const reader = new FileReader();
            reader.onload = (e) => {
                pre.textContent = e.target.result;
            };
            reader.readAsText(blob);
            previewContent.appendChild(pre);
        } else {
            const msg = document.createElement("p");
            msg.innerText = "Preview not available for this file type. Use the download button above.";
            msg.className = "text-gray-400 text-center py-8";
            previewContent.appendChild(msg);
        }
        container.appendChild(previewContent);

        modal.classList.remove("hidden");
        // Disable close for public view? Or redirect to home
        document.getElementById("close-preview").onclick = () => {
            window.location.href = "/";
        };

    } catch (e) {
        console.error(e);
        alert("Failed to open public link: " + e.message);
    }
}

async function previewFile(fileId, ownerUsername = null) {
    const userToUse = ownerUsername || currentUser;
    const res = await fetch(`${API_URL}/download/${fileId}`, {
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    const data = await res.json();

    if (!data.ok) return alert(data.msg);

    try {
        const encryptedContent = base64ToArrayBuffer(data.file_content_b64);
        const decryptedBuffer = await decryptFile(
            encryptedContent,
            data.encrypted_key,
            data.iv,
            encryptionKeyPair.privateKey
        );

        const blob = new Blob([decryptedBuffer]);
        const url = URL.createObjectURL(blob);

        // Show Modal
        const modal = document.getElementById("preview-modal");
        const container = document.getElementById("preview-container");
        const title = document.getElementById("preview-title");

        title.innerText = data.filename;
        container.innerHTML = "";

        // Add Download Button
        const downloadBtn = document.createElement("button");
        downloadBtn.innerText = "Download File";
        downloadBtn.style.marginBottom = "1rem";
        downloadBtn.onclick = () => {
            const a = document.createElement("a");
            a.href = url;
            a.download = data.filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        };
        container.appendChild(downloadBtn);

        // Add Share Buttons (Only if I am the owner)
        if (data.filename && !ownerUsername) {
            const shareBtn = document.createElement("button");
            shareBtn.innerText = "Share to User";
            shareBtn.style.marginLeft = "0.5rem";
            shareBtn.style.marginBottom = "1rem";
            shareBtn.style.backgroundColor = "#10b981"; // Green
            shareBtn.onclick = () => shareFile(fileId);
            container.appendChild(shareBtn);

            const publicBtn = document.createElement("button");
            publicBtn.innerText = "Create Public Link";
            publicBtn.style.marginLeft = "0.5rem";
            publicBtn.style.marginBottom = "1rem";
            publicBtn.style.backgroundColor = "#f59e0b"; // Amber
            publicBtn.onclick = () => createPublicLink(fileId);
            container.appendChild(publicBtn);
        }

        // Add Preview Content
        const previewContent = document.createElement("div");
        previewContent.className = "w-full";

        if (data.filename.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i)) {
            const img = document.createElement("img");
            img.src = url;
            img.className = "max-w-full max-h-[70vh] mx-auto rounded";
            previewContent.appendChild(img);
        } else if (data.filename.match(/\.(mp4|webm|ogg)$/i)) {
            const video = document.createElement("video");
            video.src = url;
            video.controls = true;
            video.className = "max-w-full max-h-[70vh] mx-auto rounded";
            previewContent.appendChild(video);
        } else if (data.filename.match(/\.(mp3|wav|ogg|m4a)$/i)) {
            const audio = document.createElement("audio");
            audio.src = url;
            audio.controls = true;
            audio.className = "w-full";
            previewContent.appendChild(audio);
        } else if (data.filename.match(/\.pdf$/i)) {
            const iframe = document.createElement("iframe");
            iframe.src = url;
            iframe.className = "w-full h-[70vh] rounded";
            previewContent.appendChild(iframe);
        } else if (data.filename.match(/\.(txt|csv|json|md|log)$/i)) {
            const pre = document.createElement("pre");
            pre.className = "bg-slate-900 p-4 rounded text-sm text-gray-300 overflow-auto max-h-[70vh]";
            const reader = new FileReader();
            reader.onload = (e) => {
                pre.textContent = e.target.result;
            };
            reader.readAsText(blob);
            previewContent.appendChild(pre);
        } else {
            const msg = document.createElement("p");
            msg.innerText = "Preview not available for this file type. Use the download button above.";
            msg.className = "text-gray-400 text-center py-8";
            previewContent.appendChild(msg);
        }
        container.appendChild(previewContent);

        modal.classList.remove("hidden");

        // Cleanup on close
        document.getElementById("close-preview").onclick = () => {
            modal.classList.add("hidden");
            URL.revokeObjectURL(url);
        };

    } catch (e) {
        console.error(e);
        alert("Decryption failed! Do you have the right key?");
    }
}

// --- Key Export/Import Utils ---

async function exportKeysToFile(username, signKeys, encKeys) {
    // Export Private Keys (JWK format for portability)
    const signPriv = await window.crypto.subtle.exportKey("jwk", signKeys.privateKey);
    const encPriv = await window.crypto.subtle.exportKey("jwk", encKeys.privateKey);

    const keyData = {
        username,
        signingKey: signPriv,
        encryptionKey: encPriv
    };

    const blob = new Blob([JSON.stringify(keyData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${username}_keys.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

async function importKeysFromFile(file) {
    const text = await file.text();
    const keyData = JSON.parse(text);

    if (!keyData.username || !keyData.signingKey || !keyData.encryptionKey) {
        throw new Error("Invalid key file format");
    }

    // Import Keys
    const signPriv = await window.crypto.subtle.importKey(
        "jwk",
        keyData.signingKey,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
    );

    const encPriv = await window.crypto.subtle.importKey(
        "jwk",
        keyData.encryptionKey,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
    );

    signingKeyPair = { privateKey: signPriv };
    encryptionKeyPair = { privateKey: encPriv };
    currentUser = keyData.username;

    // Fetch Public Encryption Key from Server to complete the KeyPair
    // This is required because we need the Public Key to encrypt files for ourselves (upload)
    try {
        const res = await fetch(`${API_URL}/keys/${currentUser}`);
        const data = await res.json();
        if (data.ok) {
            const encPub = await window.crypto.subtle.importKey(
                "spki",
                base64ToArrayBuffer(data.encryption_public_key_pem.replace(/-----BEGIN PUBLIC KEY-----|\n|-----END PUBLIC KEY-----/g, "")),
                { name: "RSA-OAEP", hash: "SHA-256" },
                true,
                ["encrypt"]
            );
            encryptionKeyPair.publicKey = encPub;
        } else {
            console.warn("Could not fetch public key from server");
        }
    } catch (e) {
        console.error("Failed to fetch public key", e);
    }

    // Save to IndexedDB for persistence
    await saveKeys(currentUser, signingKeyPair, encryptionKeyPair);

    return currentUser;
}

// --- Admin Dashboard Logic ---

const btnAdmin = document.getElementById("btn-admin");
const viewAdmin = document.getElementById("view-admin");

if (btnAdmin) {
    btnAdmin.onclick = () => {
        // Hide other views
        [viewFiles, viewShared, viewManage, viewSecurity].forEach(v => {
            if (v) v.classList.add("hidden");
        });
        [tabFiles, tabShared, tabManage, tabSecurity].forEach(t => {
            if (t) {
                t.classList.remove("text-blue-600", "border-b-2", "border-blue-600");
                t.classList.add("text-gray-500");
            }
        });

        viewAdmin.classList.remove("hidden");
        loadAdminDashboard();
    };
}

async function loadAdminDashboard() {
    try {
        // Fetch Stats
        const resStats = await fetch(`${API_URL}/admin/stats`, {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const stats = await resStats.json();
        if (stats.ok) {
            document.getElementById("admin-total-users").innerText = stats.user_count || 0;
            document.getElementById("admin-total-storage").innerText = formatBytes(stats.total_storage || 0);
            document.getElementById("admin-active-sessions").innerText = stats.active_sessions || 0;
        } else {
            showToast("Failed to load admin stats", 'error');
        }

        // Fetch Users
        const resUsers = await fetch(`${API_URL}/admin/users`, {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const dataUsers = await resUsers.json();
        if (dataUsers.ok) {
            renderUserTable(dataUsers.users);
        } else {
            showToast("Failed to load users", 'error');
        }
    } catch (error) {
        console.error("Admin dashboard error:", error);
        showToast("Error loading admin dashboard", 'error');
    }
}

function renderUserTable(users) {
    const tbody = document.getElementById("admin-user-list");
    tbody.innerHTML = "";

    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-8 text-center text-gray-400">No users found</td></tr>';
        return;
    }

    users.forEach(u => {
        const tr = document.createElement("tr");
        tr.className = `hover:bg-slate-800/50 transition-colors ${u.is_suspended ? 'opacity-60' : ''}`;
        tr.innerHTML = `
            <td class="px-6 py-4 font-medium text-white">
                ${u.username}
                ${u.is_suspended ? '<span class="ml-2 text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded border border-red-500/30">⛔ Suspended</span>' : ''}
            </td>
            <td class="px-6 py-4 text-gray-300">${formatBytes(u.storage_used)}</td>
            <td class="px-6 py-4 text-gray-300">${u.file_count || 0}</td>
            <td class="px-6 py-4">
                <span class="${u.is_admin ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : 'bg-slate-700 text-slate-300'} px-2 py-1 rounded text-xs border">
                    ${u.is_admin ? '👑 Admin' : 'User'}
                </span>
            </td>
            <td class="px-6 py-4">
                <div class="flex gap-2">
                    ${!u.is_admin ? `
                        ${!u.is_suspended ? `
                            <button onclick="promoteUser(${u.id}, '${u.username}')" 
                                    class="px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-xs rounded transition-colors"
                                    title="Promote to Admin">
                                👑 Promote
                            </button>
                            <button onclick="adjustQuota(${u.id}, '${u.username}', ${u.storage_quota})" 
                                    class="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded transition-colors"
                                    title="Adjust Storage Quota">
                                💾 Quota
                            </button>
                            <button onclick="suspendUser(${u.id}, '${u.username}')" 
                                    class="px-3 py-1 bg-orange-600 hover:bg-orange-700 text-white text-xs rounded transition-colors"
                                    title="Suspend User">
                                ⛔ Suspend
                            </button>
                            <button onclick="deleteUser(${u.id}, '${u.username}')" 
                                    class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
                                    title="Delete User">
                                🗑️ Delete
                            </button>
                        ` : `
                            <button onclick="unsuspendUser(${u.id}, '${u.username}')" 
                                    class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-xs rounded transition-colors"
                                    title="Unsuspend User">
                                ✅ Unsuspend
                            </button>
                            <button onclick="deleteUser(${u.id}, '${u.username}')" 
                                    class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
                                    title="Delete User">
                                🗑️ Delete
                            </button>
                        `}
                    ` : '<span class="text-gray-500 text-xs">Admin Account</span>'}
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to delete user "${username}"? This will delete all their files and cannot be undone.`)) return;

    try {
        const res = await fetch(`${API_URL}/admin/users/${userId}`, {
            method: 'DELETE',
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (data.ok) {
            showToast(`User "${username}" deleted successfully`, 'success');
            loadAdminDashboard();
        } else {
            showToast("Error: " + data.msg, 'error');
        }
    } catch (error) {
        console.error("Delete user error:", error);
        showToast("Failed to delete user", 'error');
    }
}

async function promoteUser(userId, username) {
    if (!confirm(`Promote "${username}" to administrator?`)) return;

    try {
        const res = await fetch(`${API_URL}/admin/users/${userId}/promote`, {
            method: 'POST',
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (data.ok) {
            showToast(`"${username}" is now an admin!`, 'success');
            loadAdminDashboard();
        } else {
            showToast("Error: " + data.msg, 'error');
        }
    } catch (error) {
        console.error("Promote user error:", error);
        showToast("Failed to promote user", 'error');
    }
}

async function adjustQuota(userId, username, currentQuota) {
    const quotaMB = Math.round(currentQuota / (1024 * 1024));
    const newQuotaMB = prompt(`Enter new storage quota for "${username}" (in MB):`, quotaMB);

    if (!newQuotaMB || isNaN(newQuotaMB)) return;

    const newQuotaBytes = parseInt(newQuotaMB) * 1024 * 1024;

    try {
        const res = await fetch(`${API_URL}/admin/users/${userId}/quota`, {
            method: 'POST',
            headers: {
                "Authorization": `Bearer ${authToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ quota: newQuotaBytes })
        });
        const data = await res.json();
        if (data.ok) {
            showToast(`Quota updated to ${newQuotaMB} MB for "${username}"`, 'success');
            loadAdminDashboard();
        } else {
            showToast("Error: " + data.msg, 'error');
        }
    } catch (error) {
        console.error("Adjust quota error:", error);
        showToast("Failed to adjust quota", 'error');
    }
}

async function suspendUser(userId, username) {
    if (!confirm(`Suspend user "${username}"? They will be immediately logged out and unable to login until unsuspended.`)) return;

    try {
        const res = await fetch(`${API_URL}/admin/users/${userId}/suspend`, {
            method: 'POST',
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (data.ok) {
            showToast(`User "${username}" has been suspended`, 'success');
            loadAdminDashboard();
        } else {
            showToast("Error: " + data.msg, 'error');
        }
    } catch (error) {
        console.error("Suspend user error:", error);
        showToast("Failed to suspend user", 'error');
    }
}

async function unsuspendUser(userId, username) {
    if (!confirm(`Unsuspend user "${username}"? They will be able to login again.`)) return;

    try {
        const res = await fetch(`${API_URL}/admin/users/${userId}/unsuspend`, {
            method: 'POST',
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (data.ok) {
            showToast(`User "${username}" has been unsuspended`, 'success');
            loadAdminDashboard();
        } else {
            showToast("Error: " + data.msg, 'error');
        }
    } catch (error) {
        console.error("Unsuspend user error:", error);
        showToast("Failed to unsuspend user", 'error');
    }
}

// Event Listeners
if (tabFiles) tabFiles.onclick = () => switchTab('files');
if (tabShared) tabShared.onclick = () => switchTab('shared');
if (tabManage) tabManage.onclick = () => switchTab('manage');
if (tabSecurity) tabSecurity.onclick = () => switchTab('security');

document.getElementById("btn-register").onclick = async () => {
    await register();
    // Auto download after register
    if (currentUser && signingKeyPair && encryptionKeyPair) {
        if (confirm("Registration successful! Do you want to download your Private Key file? (Recommended for backup)")) {
            await exportKeysToFile(currentUser, signingKeyPair, encryptionKeyPair);
        }
    }
};

document.getElementById("btn-login").onclick = login;

document.getElementById("btn-logout").onclick = async () => {
    if (confirm("Are you sure you want to logout? This will clear your session.")) {
        await clearKeys();

        // Clear State
        currentUser = null;
        signingKeyPair = null;
        encryptionKeyPair = null;

        // Clear UI Inputs
        usernameInput.value = "";
        if (document.getElementById("key-file-input")) {
            document.getElementById("key-file-input").value = "";
        }
        authStatus.innerText = "";

        location.reload();
    }
};

const keyFileInput = document.getElementById("key-file-input");
keyFileInput.onchange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    try {
        authStatus.innerText = "Importing keys...";
        const username = await importKeysFromFile(file);
        usernameInput.value = username;
        authStatus.innerText = "Keys imported! Logging in...";

        // Call login which will handle 2FA if enabled
        await login();
    } catch (err) {
        console.error(err);
        authStatus.innerText = "Error importing keys: " + err.message;
        showToast("Error importing keys: " + err.message, 'error');
    }
};

dropZone.onclick = () => fileInput.click();
fileInput.onchange = (e) => {
    if (e.target.files.length > 0) handleFileUpload(e.target.files[0]);
};
dropZone.ondragover = (e) => { e.preventDefault(); dropZone.style.borderColor = "#3b82f6"; };
dropZone.ondragleave = (e) => { e.preventDefault(); dropZone.style.borderColor = "#334155"; };
dropZone.ondrop = (e) => {
    e.preventDefault();
    dropZone.style.borderColor = "#334155";
    if (e.dataTransfer.files.length > 0) handleFileUpload(e.dataTransfer.files[0]);
};

// Setup drag and drop for moving files to folders
function setupFileDragAndDrop() {
    const fileItems = fileList.querySelectorAll('li');
    
    fileItems.forEach(item => {
        const fileId = item.getAttribute('data-file-id');
        const isFolder = item.getAttribute('data-is-folder') === 'true';
        const folderId = item.getAttribute('data-folder-id');
        
        // Make files draggable
        if (!isFolder && fileId) {
            item.addEventListener('dragstart', (e) => {
                e.dataTransfer.setData('text/plain', fileId);
                e.dataTransfer.effectAllowed = 'move';
                item.style.opacity = '0.5';
            });
            
            item.addEventListener('dragend', () => {
                item.style.opacity = '1';
            });
        }
        
        // Make folders drop zones
        if (isFolder && folderId) {
            item.addEventListener('dragover', (e) => {
                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';
                item.classList.add('border-blue-500', 'bg-blue-500/10');
            });
            
            item.addEventListener('dragleave', () => {
                item.classList.remove('border-blue-500', 'bg-blue-500/10');
            });
            
            item.addEventListener('drop', async (e) => {
                e.preventDefault();
                item.classList.remove('border-blue-500', 'bg-blue-500/10');
                
                const draggedFileId = e.dataTransfer.getData('text/plain');
                if (draggedFileId && draggedFileId !== folderId) {
                    await moveFileToFolder(draggedFileId, folderId);
                }
            });
        }
    });
}

// Move file to folder function
async function moveFileToFolder(fileId, folderId) {
    try {
        const res = await fetch(`${API_URL}/files/${fileId}/move`, {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${authToken}`
            },
            body: JSON.stringify({
                parent_id: folderId
            })
        });
        
        const data = await res.json();
        if (data.ok) {
            showToast("File moved successfully!", 'success');
            loadFiles();
        } else {
            showToast("Error: " + data.msg, 'error');
        }
    } catch (e) {
        console.error(e);
        showToast("Failed to move file", 'error');
    }
}

// Show move file modal
let currentMoveFileId = null;
async function showMoveFileModal(fileId, fileName) {
    currentMoveFileId = fileId;
    
    const modal = document.getElementById("move-file-modal");
    const fileNameEl = document.getElementById("move-file-name");
    const folderSelect = document.getElementById("move-folder-select");
    
    fileNameEl.textContent = `Moving: ${fileName}`;
    
    // Load folders
    try {
        const res = await fetch(`${API_URL}/folders/list`, {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();
        
        if (data.ok) {
            // Clear existing options except Root
            folderSelect.innerHTML = '<option value="null">Root (Home)</option>';
            
            // Add folders
            data.folders.forEach(folder => {
                const option = document.createElement("option");
                option.value = folder.id;
                option.textContent = folder.path;
                folderSelect.appendChild(option);
            });
        }
    } catch (e) {
        console.error(e);
        showToast("Failed to load folders", 'error');
    }
    
    modal.classList.remove("hidden");
}

// Move file modal handlers
const btnMoveCancel = document.getElementById("btn-move-cancel");
const btnMoveConfirm = document.getElementById("btn-move-confirm");

if (btnMoveCancel) {
    btnMoveCancel.onclick = () => {
        document.getElementById("move-file-modal").classList.add("hidden");
        currentMoveFileId = null;
    };
}

if (btnMoveConfirm) {
    btnMoveConfirm.onclick = async () => {
        if (!currentMoveFileId) return;
        
        const folderSelect = document.getElementById("move-folder-select");
        const selectedFolderId = folderSelect.value;
        
        await moveFileToFolder(currentMoveFileId, selectedFolderId);
        
        document.getElementById("move-file-modal").classList.add("hidden");
        currentMoveFileId = null;
    };
}

// Close modal when clicking outside
window.onclick = (event) => {
    const modal = document.getElementById("preview-modal");
    if (event.target == modal) {
        modal.classList.add("hidden");
    }
};

// Helper function to create menu item
function createMenuItem(text, className, onClick) {
    const item = document.createElement("button");
    item.className = `w-full text-left px-4 py-2 text-sm ${className} transition-colors flex items-center gap-2`;
    item.textContent = text;
    item.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        console.log("Menu item clicked:", text);
        try {
            onClick();
        } catch (error) {
            console.error("Error in menu item onClick:", error);
            showToast("Error: " + error.message, 'error');
        }
    };
    return item;
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

// --- 2FA and Security Logic ---

function renderUserTable(users) {
    const tbody = document.getElementById("admin-user-list");
    tbody.innerHTML = "";
    users.forEach(u => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-slate-800/50 transition-colors";
        tr.innerHTML = `
            <td class="px-6 py-4 font-medium text-white">${u.username}</td>
            <td class="px-6 py-4">${formatBytes(u.storage_used)}</td>
            <td class="px-6 py-4">${u.file_count}</td>
            <td class="px-6 py-4">
                <span class="${u.is_admin ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : 'bg-slate-700 text-slate-300'} px-2 py-1 rounded text-xs border">
                    ${u.is_admin ? 'Admin' : 'User'}
                </span>
            </td>
            <td class="px-6 py-4 text-right">
                ${!u.is_admin ? `
                <button onclick="deleteUser(${u.id})" class="text-red-400 hover:text-red-300 text-sm font-medium">
                    Delete
                </button>` : ''}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function deleteUser(userId) {
    if (!confirm("Are you sure? This will delete the user and ALL their files permanently.")) return;

    const res = await fetch(`${API_URL}/admin/users/${userId}`, {
        method: 'DELETE',
        headers: { "Authorization": `Bearer ${authToken}` }
    });

    if (res.ok) {
        loadAdminDashboard();
    } else {
        const data = await res.json();
        alert("Error: " + data.msg);
    }
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

// --- 2FA and Security Logic ---

async function loadSecurityStatus() {
    const res = await fetch(`${API_URL}/2fa/status`, {
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    const data = await res.json();
    if (data.ok) {
        const disabled = document.getElementById("2fa-disabled");
        const setup = document.getElementById("2fa-setup");
        const enabled = document.getElementById("2fa-enabled");

        if (data.enabled) {
            disabled.classList.add("hidden");
            setup.classList.add("hidden");
            enabled.classList.remove("hidden");
        } else {
            disabled.classList.remove("hidden");
            setup.classList.add("hidden");
            enabled.classList.add("hidden");
        }
    }

    // Load active sessions
    loadActiveSessions();
}

async function loadActiveSessions() {
    const res = await fetch(`${API_URL}/sessions`, {
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    const data = await res.json();
    if (data.ok) {
        const sessionsList = document.getElementById("sessions-list");
        sessionsList.innerHTML = "";

        if (data.sessions.length === 0) {
            sessionsList.innerHTML = '<li class="text-gray-500 italic">No active sessions</li>';
        } else {
            data.sessions.forEach(s => {
                const li = document.createElement("li");
                li.className = "flex justify-between items-center bg-slate-700/30 p-3 rounded";

                const infoDiv = document.createElement("div");
                const deviceDiv = document.createElement("div");
                deviceDiv.className = "text-white font-medium";
                deviceDiv.textContent = s.device_info + (s.is_current ? " (Current)" : "");

                const metaDiv = document.createElement("div");
                metaDiv.className = "text-xs text-gray-400";
                metaDiv.textContent = `${s.ip_address} • Last active: ${new Date(s.last_active).toLocaleString()}`;

                infoDiv.appendChild(deviceDiv);
                infoDiv.appendChild(metaDiv);

                li.appendChild(infoDiv);

                if (!s.is_current) {
                    const deleteBtn = document.createElement("button");
                    deleteBtn.className = "text-red-400 hover:text-red-300 text-sm";
                    deleteBtn.textContent = "Logout";
                    deleteBtn.onclick = () => deleteSession(s.id);
                    li.appendChild(deleteBtn);
                }

                sessionsList.appendChild(li);
            });
        }
    }
}

async function deleteSession(sessionId) {
    const res = await fetch(`${API_URL}/sessions/${sessionId}`, {
        method: 'DELETE',
        headers: { "Authorization": `Bearer ${authToken}` }
    });
    if (res.ok) {
        loadActiveSessions();
    }
}

// 2FA Button Handlers
const btnSetup2FA = document.getElementById("btn-setup-2fa");
if (btnSetup2FA) {
    btnSetup2FA.onclick = async () => {
        const res = await fetch(`${API_URL}/2fa/setup`, {
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (data.ok) {
            document.getElementById("qr-code-img").src = data.qr_code;
            document.getElementById("totp-secret").textContent = data.secret;
            document.getElementById("2fa-disabled").classList.add("hidden");
            document.getElementById("2fa-setup").classList.remove("hidden");
        }
    };
}

const btnEnable2FA = document.getElementById("btn-enable-2fa");
if (btnEnable2FA) {
    btnEnable2FA.onclick = async () => {
        const code = document.getElementById("2fa-code-input").value;
        if (!code || code.length !== 6) return alert("Please enter a 6-digit code");

        const res = await fetch(`${API_URL}/2fa/enable`, {
            method: 'POST',
            headers: {
                "Authorization": `Bearer ${authToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ code })
        });
        const data = await res.json();
        if (data.ok) {
            // Show backup codes
            const backupList = document.getElementById("backup-codes-list");
            backupList.innerHTML = "";
            data.backup_codes.forEach(code => {
                const div = document.createElement("div");
                div.className = "bg-slate-800 p-2 rounded text-center";
                div.textContent = code;
                backupList.appendChild(div);
            });

            document.getElementById("2fa-setup").classList.add("hidden");
            document.getElementById("2fa-enabled").classList.remove("hidden");
            document.getElementById("backup-codes-display").classList.remove("hidden");
            document.getElementById("2fa-code-input").value = "";
        } else {
            alert("Error: " + data.msg);
        }
    };
}

const btnCancel2FA = document.getElementById("btn-cancel-2fa");
if (btnCancel2FA) {
    btnCancel2FA.onclick = () => {
        document.getElementById("2fa-setup").classList.add("hidden");
        document.getElementById("2fa-disabled").classList.remove("hidden");
        document.getElementById("2fa-code-input").value = "";
    };
}

const btnDisable2FA = document.getElementById("btn-disable-2fa");
if (btnDisable2FA) {
    btnDisable2FA.onclick = async () => {
        const code = document.getElementById("2fa-disable-code").value;
        if (!code || code.length !== 6) return alert("Please enter a 6-digit code");

        const res = await fetch(`${API_URL}/2fa/disable`, {
            method: 'POST',
            headers: {
                "Authorization": `Bearer ${authToken}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ code })
        });
        const data = await res.json();
        if (data.ok) {
            document.getElementById("2fa-enabled").classList.add("hidden");
            document.getElementById("2fa-disabled").classList.remove("hidden");
            document.getElementById("2fa-disable-code").value = "";
            alert("2FA has been disabled");
        } else {
            alert("Error: " + data.msg);
        }
    };
}

const btnCloseBackup = document.getElementById("btn-close-backup");
if (btnCloseBackup) {
    btnCloseBackup.onclick = () => {
        document.getElementById("backup-codes-display").classList.add("hidden");
    };
}

const btnLogoutAll = document.getElementById("btn-logout-all");
if (btnLogoutAll) {
    btnLogoutAll.onclick = async () => {
        if (!confirm("Logout all other devices?")) return;

        const res = await fetch(`${API_URL}/sessions/all`, {
            method: 'DELETE',
            headers: { "Authorization": `Bearer ${authToken}` }
        });
        const data = await res.json();
        if (data.ok) {
            alert(`Logged out ${data.deleted} session(s)`);
            loadActiveSessions();
        }
    };
}

// 2FA Login Modal Handlers
const btn2FAVerify = document.getElementById("btn-2fa-verify");
const btn2FACancel = document.getElementById("btn-2fa-cancel");

if (btn2FAVerify) {
    btn2FAVerify.onclick = async () => {
        const code = document.getElementById("login-2fa-code").value;
        if (!code || code.length !== 6) {
            showToast("Please enter a 6-digit code", 'warning');
            return;
        }

        if (!window.pendingLogin) {
            showToast("No pending login found", 'error');
            return;
        }

        const { username, challenge, signature } = window.pendingLogin;

        const res = await fetch(`${API_URL}/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username,
                challenge,
                signature,
                totp_code: code
            })
        });

        const data = await res.json();
        if (data.ok) {
            currentUser = username;
            authToken = data.token;

            if (data.is_admin) {
                document.getElementById("btn-admin").classList.remove("hidden");
            } else {
                document.getElementById("btn-admin").classList.add("hidden");
            }

            await saveKeys(currentUser, signingKeyPair, encryptionKeyPair, data.is_admin);

            document.getElementById("2fa-input-modal").classList.add("hidden");
            document.getElementById("login-2fa-code").value = "";
            window.pendingLogin = null;

            showDashboard();
            showToast("Login successful!", 'success');
        } else {
            // Show error toast with clear message
            showToast("❌ Invalid 2FA code. Please try again.", 'error');

            // Clear the input and refocus for retry
            const codeInput = document.getElementById("login-2fa-code");
            codeInput.value = "";
            codeInput.focus();
        }
    };
}

if (btn2FACancel) {
    btn2FACancel.onclick = () => {
        document.getElementById("2fa-input-modal").classList.add("hidden");
        document.getElementById("login-2fa-code").value = "";
        window.pendingLogin = null;
    };
}

// 2FA Reminder Modal Handlers
const btnRemindLater = document.getElementById("btn-remind-later");
const btnSetupNow = document.getElementById("btn-setup-now");

if (btnRemindLater) {
    btnRemindLater.onclick = () => {
        document.getElementById("2fa-reminder-modal").classList.add("hidden");
    };
}

if (btnSetupNow) {
    btnSetupNow.onclick = () => {
        document.getElementById("2fa-reminder-modal").classList.add("hidden");
        // Switch to security tab
        switchTab('security');
        // Trigger 2FA setup
        setTimeout(() => {
            const btnSetup2FA = document.getElementById("btn-setup-2fa");
            if (btnSetup2FA) {
                btnSetup2FA.click();
            }
        }, 300);
    };
}
