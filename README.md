# Post-Quantum OpenID Connect (KEMTLS + Dilithium)

## Project Overview
This project implements a Post-Quantum Secure OpenID Connect (OIDC) system. It replaces standard TLS with **KEMTLS** (using ML-KEM-768/Kyber) for transport security and uses **ML-DSA-65 (Dilithium3)** for Identity Token signatures. This ensures protection against both "Store-Now-Decrypt-Later" attacks and quantum signature forgery.

## Features
- **Transport Layer:** Custom KEMTLS handshake replacing standard TLS 1.3.
- **Application Layer:** OIDC Identity Tokens signed with NIST-standard Dilithium.
- **Architecture:** Node.js-based Identity Provider (IDP), Relying Party (RP), and User Agent (UA).

## Prerequisites
- Node.js (v16 or higher)
- NPM

## Installation

1. Navigate to the source code directory:
   ```bash
   cd Source_Code

    ```

2. Install dependencies (including the Dilithium crypto library):
    ```bash
    npm install
    npm install dilithium-crystals-js

    ```

## How to Run

Open three separate terminals to simulate the three network entities:

**Terminal 1 (Relying Party):**

```bash
node RP.js

```

**Terminal 2 (Identity Provider):**

```bash
node IDP.js

```

**Terminal 3 (User Agent/Client):**

```bash
node UA.js

```

## Usage Flow

1. The **User Agent (UA)** connects to the RP and IDP using a KEMTLS handshake.
2. The UA requests a protected resource from the RP.
3. The RP redirects the UA to the IDP for authentication.
4. The User logs in (default creds: `alice` / `password123`).
5. The IDP issues a **Dilithium-Signed ID Token**.
6. The RP verifies the post-quantum signature and grants access.

```
