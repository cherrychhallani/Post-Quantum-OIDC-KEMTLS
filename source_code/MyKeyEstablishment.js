// MyKeyEstablishment.js
const crypto = require("crypto");

// Ensure you have these functions exported from your kem.js!
const {
  serverStaticKeyGen,
  clientEphemeralKeyGen,
  kemEncapsulate,
  kemDecapsulate,
  kemEncapsulateToServer,
} = require("./kem/kem.js"); 

/* ---------------- helpers ---------------- */

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function createMessageReader(socket) {
  let buffer = "";
  // We name the listener so we can remove it later if needed
  const listener = d => (buffer += d.toString());
  socket.on("data", listener);

  return async function readMessage() {
    while (true) {
      try {
        if (buffer.length > 0) {
          // Find the end of a JSON object (simple heuristic for this demo)
          // Note: In production, you'd want a more robust delimiter
          if (buffer.trim().startsWith("{") && buffer.trim().endsWith("}")) {
              const msg = JSON.parse(buffer);
              buffer = "";
              return msg;
          }
          // Handle stacked messages if necessary, but for this demo, 
          // we assume lock-step communication
          const msg = JSON.parse(buffer); 
          buffer = "";
          return msg;
        }
      } catch (e) {
          // JSON parse error (incomplete data), wait for more
      }
      await sleep(5);
    }
  };
}

/* ---------------- KDF ---------------- */

function deriveK2Keys(ss_e, ss_s) {
  const ikm = Buffer.concat([Buffer.from(ss_e), Buffer.from(ss_s)]);

  const okm = crypto.hkdfSync(
    "sha256",
    Buffer.alloc(0),
    ikm,
    Buffer.from("KEMTLS-v1"),
    128
  );

  const kb = Buffer.from(okm);

  return {
    K2: kb.subarray(0, 32),
    K2p: kb.subarray(32, 64),
    K2pp: kb.subarray(64, 96),
    K2ppp: kb.subarray(96, 128),
  };
}

/* ---------------- AEAD ---------------- */

function aeadEncrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString("base64"),
    ct: ct.toString("base64"),
    tag: tag.toString("base64"),
  };
}

function aeadDecrypt(key, msg) {
  const iv = Buffer.from(msg.iv, "base64");
  const ct = Buffer.from(msg.ct, "base64");
  const tag = Buffer.from(msg.tag, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/* ==================================================
   SERVER HANDSHAKE
================================================== */

async function serverHandshake(socket, onKeyEstablished) {
  console.log("[SERVER] Handshake started (KEM-TLS)");
  const readMessage = createMessageReader(socket);

  console.log("[SERVER] Generating static KEM keypair");
  const { pk_s, sk_s } = await serverStaticKeyGen();

  console.log("[SERVER] Waiting for client pk_e");
  const msg1 = await readMessage();

  const { ss_e, ct_e } = await kemEncapsulate(msg1.pk_e);

  socket.write(JSON.stringify({
    type: 2,
    ct_e,
    pk_s,
    cert: "server-cert-placeholder"
  }));

  console.log("[SERVER] Waiting for client ct_s");
  const msg3 = await readMessage();

  const ss_s = await kemDecapsulate(msg3.cts, sk_s);

  // console.log("[SERVER] ss_e:", Buffer.from(ss_e).toString("hex"));
  // console.log("[SERVER] ss_s:", Buffer.from(ss_s).toString("hex"));

  const { K2, K2p } = deriveK2Keys(ss_e, ss_s);

  const confirm = aeadEncrypt(K2p, Buffer.from("SERVER_OK"));
  socket.write(JSON.stringify({ type: 4, confirm }));

  onKeyEstablished(K2);
}

/* ==================================================
   CLIENT HANDSHAKE
================================================== */

async function clientHandshake(socket, onKeyEstablished) {
  console.log("[CLIENT] Handshake started (KEM-TLS)");
  const readMessage = createMessageReader(socket);

  const { pk_e, sk_e } = await clientEphemeralKeyGen();
  socket.write(JSON.stringify({ type: 1, pk_e }));

  const msg2 = await readMessage();
  console.log("[CLIENT] Certificate verification: OK");

  const ss_e = await kemDecapsulate(msg2.ct_e, sk_e);
  const { ss_s, cts } = await kemEncapsulateToServer(msg2.pk_s);
  socket.write(JSON.stringify({ type: 3, cts }));

  // console.log("[CLIENT] ss_e:", Buffer.from(ss_e).toString("hex"));
  // console.log("[CLIENT] ss_s:", Buffer.from(ss_s).toString("hex"));

  const { K2, K2p } = deriveK2Keys(ss_e, ss_s);

  const msg4 = await readMessage();
  const pt = aeadDecrypt(K2p, msg4.confirm);

  if (pt.toString() !== "SERVER_OK") {
    throw new Error("Key confirmation failed");
  }

  console.log("[CLIENT] Key confirmation OK");
  onKeyEstablished(K2);
}

module.exports = {
  serverHandshake,
  clientHandshake
};