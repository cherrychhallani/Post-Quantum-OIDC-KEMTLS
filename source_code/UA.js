const readline = require("readline");
const { Alice, Bob, Eve } = require("./config");
const { createConnectionAPI } = require("./connection");
const { createProtectedResourceRequest } = require("./message/message_ua");
const { delay } = require("./utils"); 
const { performance } = require("perf_hooks");


const mySelf = Alice;
const RP = Bob;
const IDP = Eve;

let responseResolver = null;

// Helper to ask user questions in the terminal
function promptUser(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function onMessage(peerId, payload) {
  let msgObj;
  try { msgObj = JSON.parse(payload.toString()); } catch (e) { return; }
  
  console.log(`[UA] Received ${msgObj.type} from ${peerId}`);
  
  // If the main loop is waiting for a message, resolve it now
  if (responseResolver) {
    const resolve = responseResolver;
    responseResolver = null;
    resolve(msgObj);
  }
}

const { GetSSK, SendRaw, connections } = createConnectionAPI(mySelf, onMessage);

function receiveNext() {
  return new Promise(resolve => { responseResolver = resolve; });
}

async function createConnection(target) {
    const t0 = performance.now();

    await GetSSK(target);   // 🔐 FULL KEMTLS HANDSHAKE

    const t1 = performance.now();

    console.log(
      `[BENCH] KEMTLS Handshake Time (${target.id}): ${(t1 - t0).toFixed(3)} ms`
    );

    return connections.get(target.id).socket;
}


(async () => {
  console.log("[UA] Establishing Connections...");
  await delay(2000); 
  const socketRP = await createConnection(RP);
  const socketIDP = await createConnection(IDP);

  // 1. UA -> RP (I want dashboard)
  console.log("[UA] Sending PROTECTED_RESOURCE_REQUEST to RP");
  await delay(2000); 

  const req1 = createProtectedResourceRequest("/dashboard");
  await SendRaw(socketRP, Buffer.from(JSON.stringify(req1)));

  // 2. RP -> UA (Go to IDP)
  // RP sends us an AUTHORIZATION_REQUEST to forward to IDP
  const msg2 = await receiveNext(); 
  
  // 3. UA -> IDP (Forwarding Auth Request)
  console.log("[UA] Forwarding AUTHORIZATION_REQUEST to IDP");
  await delay(2000); 

  await SendRaw(socketIDP, Buffer.from(JSON.stringify(msg2)));

  // 4. IDP -> UA (HERE IS THE LOGIN FORM)
  const formMsg = await receiveNext(); 
  
  if (formMsg.type === "LOGIN_FORM_REQUEST") {
    console.log("\n" + "=".repeat(30));
    console.log("   BROWSER: IDP LOGIN PAGE   ");
    console.log("=".repeat(30));
    console.log(`Message: ${formMsg.payload.message}`);
    
    // INTERACTIVE PROMPT
    const username = await promptUser("Username: ");
    const password = await promptUser("Password: ");
    const consent  = await promptUser("Allow access to Profile? (yes/no): ");
    
    const submission = {
      type: "LOGIN_SUBMISSION",
      from: "USER_AGENT",
      to: "IDENTITY_PROVIDER",
      payload: { username, password, consent }
    };

    console.log("\n[UA] Submitting credentials to IDP...");
    await delay(2000); 

    await SendRaw(socketIDP, Buffer.from(JSON.stringify(submission)));
  }

  // 5. IDP -> UA (Auth Code)
  const authResponse = await receiveNext(); 
  
  if (authResponse.type === "LOGIN_ERROR") {
    console.error(`[UA] Login Failed: ${authResponse.payload.error}`);
    process.exit(1);
  }

  // 6. UA -> RP (Forwarding Auth Code)
  console.log("[UA] Received Code. Forwarding to RP...");
  await delay(2000); 

  await SendRaw(socketRP, Buffer.from(JSON.stringify(authResponse)));

  // 7. RP -> UA (Access Granted / Success)
  const finalMsg = await receiveNext(); 

  // FIX: Check for "LOGIN_SUCCESS" instead of "ACCESS_GRANTED"
  if (finalMsg && finalMsg.type === "LOGIN_SUCCESS") {
    console.log("\n" + "=".repeat(40));
    console.log("✅ SUCCESS: " + finalMsg.payload.message);
    console.log("   User:    " + finalMsg.payload.user);
    console.log("=".repeat(40) + "\n");
    process.exit(0);
  } else {
    // Keep this for debugging if something else comes in
    console.log("❌ FAILURE: Unexpected message type received.");
    console.log("   Received:", finalMsg);
    process.exit(1);
  }

})();