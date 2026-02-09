const { Bob, Eve } = require("./config");
const { startServer } = require("./server");
const { createConnectionAPI } = require("./connection");
const { 
  createAuthorizationRequest, 
  createTokenRequest
} = require("./message/message_rp");
const { performance } = require("perf_hooks");

// --- IMPORT THE NEW WRAPPER ---
const { verifyDilithium } = require("./Algo/dilithium_wrapper.js");
const { delay } = require("./utils");

const mySelf = Bob; 
const IDP = Eve;
const { SendRaw, connections, GetSSK } = createConnectionAPI(mySelf, onMessage);

let uaPeerId = null;       
let pendingState = null;   

async function onMessage(peerId, payload, socket) {
  let msgObj;
  try { msgObj = JSON.parse(payload.toString()); } catch (e) { return; }

  console.log(`[RP] Received ${msgObj.type} from ${peerId}`);

  if (msgObj.type === "PROTECTED_RESOURCE_REQUEST") {
    uaPeerId = peerId;
    console.log(`[RP] UA identified as "${uaPeerId}". Initiating OIDC Flow...`);
    const authReq = createAuthorizationRequest("openid profile");
    pendingState = authReq.payload.params.state;
    await delay(1000);
    await SendRaw(socket, Buffer.from(JSON.stringify(authReq)));
  }

  else if (msgObj.type === "AUTHORIZATION_RESPONSE") {
    const { code, state } = msgObj.payload.params;

    if (state !== pendingState) { return; }
    
    console.log(`[RP] State Verified. Swapping Code for Token...`);
    await delay(1000);

    await GetSSK(IDP); 
    const idpSocket = connections.get(IDP.id).socket;
    const tokenReq = createTokenRequest(code);
    await SendRaw(idpSocket, Buffer.from(JSON.stringify(tokenReq)));
  }

  else if (msgObj.type === "TOKEN_RESPONSE") {
    const { id_token, public_key } = msgObj.payload;
    console.log("[RP] Received Token. Verifying Post-Quantum (ML-DSA) Signature...");

    const parts = id_token.split('.');
    const content = parts[0] + "." + parts[1];
    const signatureB64URL = parts[2];

    // Convert Base64URL to Standard Base64 for the library
    let signatureStandard = signatureB64URL.replace(/-/g, '+').replace(/_/g, '/');
    while (signatureStandard.length % 4 !== 0) signatureStandard += '=';

    // Verify using Dilithium
    const tVerifyStart = performance.now();

const isValid = await verifyDilithium(content, signatureStandard, public_key);

const tVerifyEnd = performance.now();

console.log(
  `[BENCH] Token Verification Time (Dilithium): ${(tVerifyEnd - tVerifyStart).toFixed(3)} ms`
);


    if (isValid) {
        console.log("✅ [RP] ML-DSA Signature VERIFIED. User is Authenticated.");
        const payloadToken = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        console.log("   User:", payloadToken.sub);

        if (uaPeerId && connections.has(uaPeerId)) {
            const successMsg = {
                type: "LOGIN_SUCCESS",
                payload: {
                    message: "Welcome! You have successfully accessed the Protected Resource.",
                    user: payloadToken.sub
                }
            };
            const uaSocket = connections.get(uaPeerId).socket;
            await SendRaw(uaSocket, Buffer.from(JSON.stringify(successMsg)));
        }
    } else {
        console.log("❌ [RP] Signature Verification FAILED!");
    }
  }
}

(async () => {
  await startServer(mySelf, connections, onMessage);
})();