# Project Overview: SecureVault (Zero-Knowledge Cloud Storage) v2

## 1. Project Identity
**Name:** SecureVault v2
**Core Concept:** A web-based file storage and sharing application that guarantees **Zero-Knowledge Privacy**. The server stores user data but mathematically cannot read it.
**Tagline:** "Trust Mathematics, Not Corporations."

## 2. Problem Statement (Latar Belakang Masalah)
Traditional cloud storage services (Google Drive, Dropbox) use **Server-Side Encryption**. They hold the keys to your data.
*   **Risk 1 (External):** If the server is hacked, keys are stolen, data is exposed.
*   **Risk 2 (Internal):** Rogue employees can view user files.
*   **Risk 3 (Legal/Political):** Service providers can be compelled to scan or hand over data.

**SecureVault's Solution:** **Client-Side Encryption (End-to-End Encryption)**.
*   Encryption happens **in the browser** before data ever leaves the device.
*   The server only receives encrypted "blobs" and encrypted keys.
*   The server **never** sees the plaintext data, plaintext filenames, or the actual decryption keys.

## 3. Comprehensive Technology Stack & Frameworks

SecureVault v2 is built using a modern, performant, and secure stack, split into a monolithic frontend Single Page Application (SPA) and a lightweight REST API backend.

### 3.1 Frontend Ecosystem (The Trust Anchor)
The frontend is responsible for ALL cryptographic operations (encryption/decryption, key generation, signing) to guarantee Zero-Knowledge Privacy.
*   **Core Framework:** **SolidJS** (`solid-js`). Chosen for its fine-grained reactivity and lack of a Virtual DOM. This provides maximum performance, which is critical since the client handles heavy cryptographic workloads.
*   **Build Tool & Dev Server:** **Vite** (`vite`). Used with `vite-plugin-solid` for extremely fast hot-module replacement during development and highly optimized production builds.
*   **Styling:** **TailwindCSS** (`tailwindcss`), with `postcss` and `autoprefixer`. Used for utility-first, modern UI development to ensure a responsive and aesthetically pleasing user interface.
*   **Cryptography:** **Native Web Crypto API**. Used inherently for all cryptographic primitives (AES-GCM, RSA-OAEP, ECDSA). Relying on the browser's native API is faster and mathematically more secure than using pure-JavaScript polyfills.
*   **File Handling & Previews:**
    *   `cropperjs`: For image manipulation and cropping capabilities.
    *   `mammoth`: For parsing and previewing `.docx` (Microsoft Word) documents natively in the browser without relying on external services.
    *   `xlsx`: For parsing and previewing Excel spreadsheets locally.
*   **Utilities:**
    *   `qrcode`: Used for generating QR codes locally (crucial for the Secure Device Linking feature and 2FA setup without sending secrets to the server).
    *   `ua-parser-js`: For parsing User-Agent strings to identify devices and browsers in active session management.
*   **Testing Infrastructure:**
    *   `vitest`: For unit and component testing.
    *   `@playwright/test`: For robust End-to-End (E2E) testing, including UI and smoke tests (`playwright test --ui`).
    *   `jsdom`: For simulating the DOM environment in unit tests.

### 3.2 Backend Ecosystem (The Blind Store)
The backend acts strictly as an authentication verifier (using digital signatures) and a dumb storage system for encrypted blobs. It never has access to plaintext data.
*   **Core Framework:** **Fastify** (`fastify`). A highly performant, low-overhead Node.js web framework designed for maximum speed.
*   **Fastify Ecosystem Plugins:**
    *   `@fastify/cookie`: For parsing and handling HTTP cookies securely.
    *   `@fastify/cors`: For Cross-Origin Resource Sharing configuration.
    *   `@fastify/helmet`: For setting essential HTTP security headers to protect against common web vulnerabilities.
    *   `@fastify/multipart`: For streaming and handling large encrypted file uploads (multipart/form-data) efficiently.
    *   `@fastify/rate-limit`: For API rate limiting to prevent brute-force or DDoS attacks on auth routes.
    *   `@fastify/static`: For serving static files (used to serve the frontend SPA in production).
*   **Database & ORM:**
    *   **Database Engine:** **SQLite** (via `better-sqlite3`). Chosen for its simplicity, self-containment, and extreme performance for this scale of application.
    *   **ORM:** **Drizzle ORM** (`drizzle-orm`). A headless, type-safe TypeScript ORM that provides SQL-like syntax and strict type safety without the overhead of heavy ORMs.
    *   **Migration CLI:** `drizzle-kit`. Used for generating SQL migrations (`db:generate`), applying them (`db:migrate`), and providing a local database browser (`db:studio`).
*   **Validation & Logging:**
    *   `zod`: Used for robust, schema-based request payload validation and environment variable parsing. Ensures only strictly formatted data enters the backend.
    *   `pino` & `pino-pretty`: Used for extremely fast, JSON-based structured logging.
*   **Security & Auth Utilities:**
    *   `otplib`: For processing Time-based One-Time Passwords (TOTP) for Two-Factor Authentication (2FA).
    *   `qrcode`: For generating 2FA QR codes server-side for initial setup.
*   **Development & Testing:**
    *   `typescript`: The entire backend is written in strict TypeScript.
    *   `tsx`: Used for executing TypeScript files directly during development (`npm run dev`).
    *   `vitest`: For backend unit and integration testing.

### 3.3 Infrastructure & Monorepo Tools
*   **Monorepo Management:** Managed via npm workspaces (with a root `package.json` that coordinates `backend` and `frontend` folders).
*   **Script Runners:**
    *   `concurrently`: Used to run the frontend and backend development servers simultaneously.
    *   `cross-env`: Used to set environment variables across different operating systems (e.g., setting `DEMO_MODE=true`).
    *   `wait-on`: Used to wait for the backend health check to pass before launching the frontend dev server.
*   **Containerization:** **Docker** and **Docker Compose**. The project includes a standard `Dockerfile`, a `Dockerfile.demo` for the demo deployment, and multiple compose configurations (`docker-compose.yml`, `docker-compose.prod.yml`, `docker-compose.demo.yml`) for seamless deployment and volume management (persisting SQLite data and uploaded files).

## 4. Cryptographic Implementation (The "Secret Sauce")

### 4.1 "Passwordless" Authentication (ECDSA)
*   **No Passwords:** SecureVault v2 completely eliminates passwords and password hashes (No PBKDF2, Argon2, etc.). Instead, it uses purely asymmetric cryptographic keys.
*   **Key Bundle:** Upon registration, the client generates a **Key Bundle** containing an **ECDSA Keypair** (for signing/authentication) and an **RSA-OAEP Keypair** (for encryption/sharing). This bundle is saved as a local `.json` file (`username_keys.json`).
*   **Authentication Flow (Challenge-Response):**
    1. User claims an identity (username).
    2. Server sends a random challenge string.
    3. Client reads the local Key Bundle, uses the **ECDSA Private Key (P-256)** to mathematically sign the challenge.
    4. Client sends the signature back to the server.
    5. Server verifies the signature using the stored ECDSA Public Key.
    *Result:* The server authenticates the user perfectly without any shared secrets.

### 4.2 File & Filename Encryption (AES-GCM)
*   Every file gets a **unique, random 256-bit AES Key**.
*   **File Content:** Encrypted with **AES-GCM** (Galois/Counter Mode), providing confidentiality and integrity (tamper-proofing).
*   **Filenames:** Filenames are also encrypted using AES-GCM (stored as a JSON string containing the base64 ciphertext and IV). The server truly doesn't even know what the files are named.

### 4.3 Secure File Sharing (RSA-OAEP Key Wrapping)
*   How to share a file without re-encrypting the whole thing? **Key Wrapping**.
*   **Scenario:** Alice wants to share a file with Bob.
    1. Alice's client downloads Bob's **RSA Public Key**.
    2. Alice's client takes the *existing* unencrypted AES Key for the file from her browser memory.
    3. Alice's client encrypts (wraps) that AES Key using Bob's RSA Public Key.
    4. Alice sends this "Wrapped Key" to the server.
    5. Bob logs in, downloads the "Wrapped Key", decrypts it with his RSA Private Key, gets the AES Key, and decrypts the file.
*   *Server sees:* Only the RSA-encrypted Wrapped Key.

### 4.4 Secure Device Linking (End-to-End Key Transfer)
*   To log in on a new device without manually transferring the `keys.json` file, users can scan a QR code.
*   The QR code/link contains a random `pairingId` and a highly secure, one-time `transferKey` in the URL fragment (`#p=...&s=...`). **URL fragments are never sent to the server.**
*   The primary device inherently encrypts the Key Bundle with AES-GCM using the `transferKey` and uploads the encrypted payload to the server.
*   The new device fetches the encrypted payload and decrypts it locally using the `transferKey` from its URL, securely acquiring the keys without the server ever gaining access.

## 5. Database Schema (High-Level)

*   `users`: `id` (UUID v4), `username`, `public_key_pem` (ECDSA P-256, for verification), `encryption_public_key_pem` (RSA-OAEP, for receiving shares). **No passwords stored.**
*   `files`: Stores `encrypted_key` (The AES FileKey wrapped for the owner via RSA), `iv`, `storage_path`, and the AES-encrypted `filename`.
*   `file_shares` & `public_shares`: Manages access control and wrapped keys for recipients.
*   `pending_device_links`: Temporary storage for encrypted key transfers between devices.

## 6. Key Workflows

### 6.1 Registration
1. User chooses a username.
2. Client generates **RSA Keypair** and **ECDSA Keypair**.
3. Client downloads these as a Key Bundle (`username_keys.json`).
4. Client sends **only Public Keys** to the server to create the account.

### 6.2 File Upload
1. User selects a file.
2. Client generates a random `FileKey` (AES-GCM 256).
3. Client encrypts the file content and filename with `FileKey`.
4. Client encrypts `FileKey` with User's Own RSA Public Key -> `WrappedKey`.
5. Client uploads Encrypted Content + Encrypted Name + `WrappedKey` + IV.

### 6.3 File Download
1. Client requests file metadata and `WrappedKey` from the server.
2. Client decrypts `WrappedKey` using their local RSA Private Key -> `FileKey`.
3. Client decrypts the Encrypted Filename and Encrypted Content using the recovered `FileKey`.

## 7. Security & Compliance (Audit Logging)

SecureVault implements a comprehensive **Audit Logging** system to track all critical actions for security, compliance, and administrative oversight. The audit trail is immutable to standard users and accessible only via the Admin Dashboard.

### 7.1 Data Logged per Event
Every audit record (`audit_logs` table) captures the full context of an action, ensuring accountability:
*   **Actor Identification:** `userId` and `username` (the username is retained permanently, even if the user account is deleted).
*   **Action Context:** `action` string identifier (e.g., `LOGIN`, `UPLOAD`, `USER_SUSPENDED`), `resourceType` (e.g., `FILE`, `USER`, `SESSION`), and the specific `resourceId`.
*   **Environmental Data:** Client's `ipAddress` and `userAgent`. (Note: IP and User-Agent logging is disabled/nullified in Demo Mode for privacy).
*   **Granular Details:** A flexible JSON `details` field that captures specific context for the action (e.g., target username, old quota vs. new quota, or specific device pairing IDs).

### 7.2 Tracked Action Categories
The system meticulously records actions across all major domains of the application:
*   **Authentication & Sessions:** `LOGIN`, `LOGOUT`, `DEVICE_LINK_CREATED`, `REVOKE_SESSION`, `REVOKE_ALL_SESSIONS`.
*   **File Operations:** `UPLOAD`, `DOWNLOAD`, `DELETE` (tracking when encrypted blobs are handled).
*   **Sharing & Access:** Actions related to creating or revoking encrypted file shares.
*   **User Management (Admin):** `SETUP_ADMIN`, `UPDATE_PROFILE`, `DELETE_ACCOUNT`, `USER_SUSPENDED`, `USER_UNSUSPENDED`, `USER_QUOTA_UPDATED`.

### 7.3 Administrator Visibility
Administrators can review these logs via a dedicated API endpoint (`GET /api/admin/audit-logs`) and the Admin Dashboard. The system provides pagination, sorting, and filtering capabilities (by action type or username), giving admins full visibility into system usage patterns, quota adjustments, and potential security anomalies.
