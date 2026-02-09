const { Eve } = require("./config");
const { startServer } = require("./server");
const { createConnectionAPI } = require("./connection");
const { 
  createLoginFormMessage, 
  handleLoginSubmission 
} = require("./message/message_idp");
const { delay } = require("./utils");
const crypto = require("crypto"); 
const { performance } = require("perf_hooks");


// --- IMPORT THE NEW WRAPPER ---
const { generateDilithiumKeyPair, signWithDilithium } = require("./Algo/dilithium_wrapper.js");

const mySelf = Eve;
const { SendRaw, connections } = createConnectionAPI(mySelf, onMessage);

function base64Url(str) {
  return Buffer.from(str).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

let pendingAuthParams = null;

async function onMessage(peerId, payload, socket) {
  let msgObj;
  try { msgObj = JSON.parse(payload.toString()); } catch (e) { return; }

  console.log(`[IDP] Received ${msgObj.type} from ${peerId}`);
  await delay(1000); 

  if (msgObj.type === "AUTHORIZATION_REQUEST") {
    console.log("[IDP] User requesting access. Sending Login Form...");
    pendingAuthParams = msgObj.payload.params;
    const formMsg = createLoginFormMessage();
    await SendRaw(socket, Buffer.from(JSON.stringify(formMsg)));
  }

  else if (msgObj.type === "LOGIN_SUBMISSION") {
    console.log("[IDP] Received Login Submission. Verifying...");
    await delay(1000); 

    if (!pendingAuthParams) { return; }

    const response = handleLoginSubmission(msgObj, pendingAuthParams);
    await SendRaw(socket, Buffer.from(JSON.stringify(response)));
    
    if (response.type === "AUTHORIZATION_RESPONSE") {
      pendingAuthParams = null;
    }
  }

  else if (msgObj.type === "TOKEN_REQUEST") {
    console.log("[IDP] Validating Code and issuing Post-Quantum Token (ML-DSA)...");
    
    // 1. Generate Post-Quantum Keys (Dilithium)
    const { pk, sk } = await generateDilithiumKeyPair();
    
    // 2. Create JWT Parts (Note the alg: ML-DSA-65)
    const header = { alg: "ML-DSA-65", typ: "JWT" };
    const payload = {
        sub: "alice",
        iss: "http://localhost:9002",
        aud: "dashboard-app",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
    };

    const unsignedToken = base64Url(JSON.stringify(header)) + "." + base64Url(JSON.stringify(payload));

    // 3. Sign using Dilithium
    const tSignStart = performance.now();

const signatureBase64 = await signWithDilithium(unsignedToken, sk);

const tSignEnd = performance.now();

console.log(
  `[BENCH] Token Signing Time (Dilithium): ${(tSignEnd - tSignStart).toFixed(3)} ms`
);

// ---- SIZE MEASUREMENTS ----
console.log("[SIZE] JWT header bytes:", Buffer.byteLength(JSON.stringify(header)));
console.log("[SIZE] JWT payload bytes:", Buffer.byteLength(JSON.stringify(payload)));
console.log("[SIZE] Dilithium signature bytes:", Buffer.from(signatureBase64, "base64").length);


    // 4. Format as Base64URL
    const signatureBase64Url = signatureBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    const id_token = unsignedToken + "." + signatureBase64Url;
    
    console.log(
  "[SIZE] Full ID Token bytes:",
  Buffer.byteLength(id_token)
);


    const response = {
        type: "TOKEN_RESPONSE",
        payload: {
            access_token: "at-" + crypto.randomBytes(16).toString("hex"),
            id_token: id_token,
            public_key: pk 
        }
    };
    
    await SendRaw(socket, Buffer.from(JSON.stringify(response)));
  }
}

(async () => {
  await startServer(mySelf, connections, onMessage);
})();