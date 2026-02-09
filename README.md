# Post-Quantum OpenID Connect over KEMTLS

> **A Pure Post-Quantum Identity System implementing OIDC semantics over a custom TCP transport using KEMTLS (Kyber) and Dilithium.**

![Status](https://img.shields.io/badge/Status-Research_Prototype-blue)
![Language](https://img.shields.io/badge/Language-Node.js_|_C-green)
![Crypto](https://img.shields.io/badge/Crypto-Kyber_|_Dilithium-red)

## 📜 Abstract
This project presents a novel implementation of **OpenID Connect (OIDC)** secured by **Post-Quantum Cryptography (PQC)**. unlike traditional implementations that rely on HTTP/TLS 1.3, this solution utilizes a custom **TCP-based transport layer** secured by a **KEMTLS-inspired handshake**.

The system replaces classical Diffie-Hellman key exchange with **ML-KEM-768 (Kyber)** for confidentiality and uses **ML-DSA-65 (Dilithium3)** for authentication, ensuring security against Dolev-Yao adversaries in a post-quantum era.

---

## 🚀 Key Features & USP
* **🛡️ Pure Post-Quantum Stack:** Zero reliance on classical algorithms (RSA/ECC) or hybrid handshakes.
* **⚡ KEMTLS Handshake:** Implements an implicit authentication handshake using Key Encapsulation Mechanisms (KEMs) instead of heavy TLS signatures.
* **🆔 Non-HTTP OIDC:** Decouples OIDC from the web, proving identity protocols can run over raw TCP (ideal for IoT/Microservices).
* **🔐 Session Binding:** Tokens are cryptographically bound to the post-quantum Session Secret Key (SSK) to prevent replay attacks.
* **🔗 C + Node.js Integration:** High-performance native C cryptographic implementations (via `liboqs`) bridged to a flexible Node.js runtime.

---

## 🏗️ System Architecture & Design Choices

### Cryptographic Rationale
1.  **Key Encapsulation (ML-KEM-768 / Kyber):** Selected for its NIST standardization and efficiency. Used for ephemeral key establishment to ensure **Forward Secrecy**.
2.  **Digital Signatures (ML-DSA-65 / Dilithium3):** Chosen for strong security margins. Used for entity authentication (IDP/RP) and signing Identity Tokens.
3.  **Liboqs Backend:** We utilize the open-source `liboqs` library to ensure algorithm agility and correctness of the underlying math.

### Architectural Decisions
* **Custom TCP Transport:** We avoided HTTP/HTTPS to gain full control over protocol framing and to minimize attack surface.
* **Modular Layering:** The system is strictly separated into Transport (TCP), Cryptography (WASM/C), and Application (OIDC) layers.
* **Ephemeral vs. Long-Term Keys:** Strictly separated to ensure that compromising a session key does not compromise the long-term identity of the entity.

---

## 📂 Project Structure
```text
/Post-Quantum-OIDC-KEMTLS
│
├── /Algo                     # Cryptographic wrappers
│   ├── wrapper.wasm          # C-compiled Kyber implementation
│   └── dilithium_wrapper.js  # Dilithium signature logic
│
├── /message                  # Protocol message definitions
│   ├── message_idp.js
│   ├── message_rp.js
│   └── message_ua.js
│
├── IDP.js                    # Identity Provider Server
├── RP.js                     # Relying Party Server
├── UA.js                     # User Agent (Client)
├── config.js                 # Configuration & Static Keys
├── connection.js             # TCP Socket & Handshake Logic
├── package.json              # Dependencies
└── README.md                 # Documentation

```

---

## 🛠️ Installation & Usage

### Prerequisites

* Node.js (v16.0.0 or higher)
* NPM

### Setup

1. Clone the repository and navigate to the source folder:
```bash
cd Source_Code

```


2. Install dependencies (including crypto libraries):
```bash
npm install
npm install dilithium-crystals-js

```



### Running the Demo

Open three separate terminals to simulate the network entities:

**1. Start the Relying Party (RP)**

```bash
node RP.js

```

**2. Start the Identity Provider (IDP)**

```bash
node IDP.js

```

**3. Start the User Agent (UA)**

```bash
node UA.js

```

*Follow the interactive prompts in the UA terminal to login and complete the flow.*

---

## ⚠️ Assumptions & Deviations

### Assumptions

* **Threat Model:** The network is fully untrusted (Dolev–Yao adversary).
* **Trusted Endpoints:** Client, Server, and IDP are not compromised at runtime.
* **Randomness:** Cryptographically secure randomness is available on the host machine.
* **Pre-distributed Keys:** Long-term public keys are assumed to be securely exchanged prior to the handshake (Simulated in `config.js`).

### Deviations from Standard OIDC/TLS

* **No HTTP/HTTPS:** The protocol runs over raw TCP sockets.
* **No TLS 1.3:** Replaced entirely by KEMTLS.
* **No Browser Redirects:** The flow is simulated programmatically; no HTTP 302 redirects are used.
* **No PKI Chain:** Certificate validation is simplified to direct public key verification for the scope of this prototype.

---

## 🔬 Research Impact & Significance

### Research Contribution

This project serves as a proof-of-concept for **"Post-Quantum OpenID Connect,"** demonstrating that identity protocols need not be tied to the fragility of TLS 1.3 signatures. By implementing **KEMTLS**, we showed that handshake latency can be reduced by avoiding heavy Dilithium signatures during the connection phase.

### Practical Impact

* **IoT Security:** The lightweight TCP-based approach is suitable for constrained devices where full HTTPS stacks are too heavy.
* **Future-Proofing:** Provides a blueprint for migrating critical infrastructure to Post-Quantum Cryptography before Q-Day.

---

## 🚧 Challenges Faced

1. **Liboqs Integration:** Interfacing Node.js with Native C implementations of Kyber required complex memory management and WASM compilation strategies.
2. **Protocol State Management:** Implementing OIDC flows (State/Nonce validation) over stateless TCP required building a custom session management layer.
3. **Key Binding:** Ensuring the OIDC token was cryptographically bound to the KEMTLS session key to prevent replay attacks was a significant logical hurdle.

---

## 📅 Steps Taken

1. **Literature Review:** Analyzed NIST PQC finalists and the KEMTLS whitepaper.
2. **Crypto Implementation:** Compiled `liboqs` primitives into a format usable by Node.js.
3. **Transport Layer:** Built a secure TCP socket wrapper that performs the Kyber handshake before sending data.
4. **Protocol Logic:** Implemented the OIDC 4-step flow (Request -> Auth -> Token -> Resource).
5. **Integration & Testing:** Verified the flow against Dolev-Yao assumptions and measured latency.

---

### 👥 Team

* **[Trojan Valkyries]** - *Implementation & Design*

---
