# SecureVault: End-to-End Encrypted File Sharing

This project is a Proof-of-Concept (PoC) for a secure, self-hosted file sharing system with **Zero-Knowledge Architecture**. The server stores files but cannot decrypt them. All encryption happens in the browser.

## Features (Thesis Points)
- **End-to-End Encryption (E2EE)**: Files are encrypted with AES-GCM (256-bit) before upload. Keys are wrapped with RSA-OAEP.
- **Zero-Knowledge**: Server only sees encrypted blobs. It has no access to user data.
- **Dual-Key Cryptography**:
  - **Identity**: ECDSA (P-256) for passwordless authentication.
  - **Encryption**: RSA-OAEP for secure key exchange.
- **Advanced Security**:
  - **Two-Factor Authentication (2FA)**: TOTP-based (Google Authenticator, Authy). Mandatory for enabled users.
  - **Session Management**: Active session tracking, remote logout, and auto-logout on revocation.
  - **Security Hardening**: Rate limiting (anti-brute-force), Secure Headers (HSTS, CSP, XSS Protection), and XSS-safe UI rendering.
- **Storage Quota**: Enforced 100MB storage limit per user.
- **File Previews**: Secure in-browser preview for Images, Videos, Audio, PDFs, and Code/Text files.
- **Self-Hosted**: Dockerized for easy deployment with `gunicorn` and SSL support.

## Tech Stack
- **Backend**: Python (Flask), SQLAlchemy (SQLite), Flask-Limiter.
- **Frontend**: Vanilla JS, Web Crypto API (Native Browser Standards), TailwindCSS.
- **Container**: Docker & Docker Compose.

## How to Run

### Option 1: Docker (Recommended)
1. Install Docker and Docker Compose.
2. Run:
   ```bash
   docker-compose up --build
   ```
3. Open `http://localhost:5000`.

### Option 2: Manual (Dev)
1. Install Python 3.11+.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run server:
   ```bash
   python server.py
   ```
4. Open `http://localhost:5000`.

## Usage Flow
1. **Register**: Enter a username. The browser generates keys and sends public keys to the server. Download your `keys.json` (Critical!).
2. **Login**: Authenticate using your private key (from `keys.json` or browser memory).
3. **2FA Setup**: Enable 2FA in the Security tab for extra protection.
4. **Upload**: Drag & drop a file. It is encrypted locally and uploaded.
5. **Share**: Share files securely with other users (using their public keys) or via public links.

## Thesis Implementation Details
- **Key Generation**: `window.crypto.subtle.generateKey`
- **Encryption**: `AES-GCM` (256-bit) for content, `RSA-OAEP` for key wrapping.
- **Auth**: Challenge-Response protocol using ECDSA signatures.
- **Defense**: Rate Limiting, CSP, HSTS, XSS Sanitization.
