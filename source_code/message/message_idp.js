// message_idp.js
const crypto = require("crypto");

const authorizationCodeStore = new Map();

// HARDCODED DATABASE
const VALID_USER = "alice";
const VALID_PASS = "password123";

/**
 * STEP 3A: IDP receives Auth Request -> Sends Login Form
 */
function createLoginFormMessage() {
  return {
    type: "LOGIN_FORM_REQUEST",
    from: "IDENTITY_PROVIDER",
    to: "USER_AGENT",
    payload: {
      message: "Please provide credentials and consent.",
      fields: ["username", "password", "consent"]
    }
  };
}

/**
 * STEP 3B: IDP receives Credentials -> Validates -> Sends Code
 */
function handleLoginSubmission(submissionMsg, originalAuthParams) {
  const { username, password, consent } = submissionMsg.payload;
  const { client_id, redirect_uri, scope, state, nonce } = originalAuthParams;

  console.log(`[IDP] Validating credentials for ${username}...`);

  // 1. Check Credentials
  if (username !== VALID_USER || password !== VALID_PASS) {
    return {
      type: "LOGIN_ERROR",
      payload: { error: "Invalid Credentials" }
    };
  }

  // 2. Check Consent
  if (consent !== "yes") {
    return {
      type: "LOGIN_ERROR",
      payload: { error: "Consent Denied" }
    };
  }

  // 3. Generate Code
  const code = "authcode-" + crypto.randomBytes(8).toString("hex");

  // 4. Save State
  authorizationCodeStore.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    scope,
    nonce,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60000,
    used: false
  });

  console.log(`[IDP] Login Success. Generated Code: ${code}`);

  return {
    type: "AUTHORIZATION_RESPONSE",
    from: "IDENTITY_PROVIDER",
    to: "USER_AGENT",
    payload: {
      redirectUri: redirect_uri,
      params: { code, state, client_id }
    }
  };
}

/**
 * STEP 5: Token Exchange (Server to Server)
 */
function processTokenRequest(tokenRequest) {
  const { params } = tokenRequest.payload;
  const { code, client_id, client_secret } = params;

  const record = authorizationCodeStore.get(code);

  if (!record) throw new Error("Invalid Code");
  if (record.used) throw new Error("Code Reused");
  if (record.clientId !== client_id) throw new Error("Client Mismatch");
  if (client_secret !== "rp-secret") throw new Error("Invalid Secret");

  record.used = true; // Mark used

  return {
    type: "TOKEN_RESPONSE",
    from: "IDENTITY_PROVIDER",
    to: "RELYING_PARTY",
    payload: {
      access_token: "at-" + crypto.randomBytes(16).toString("hex"),
      token_type: "Bearer",
      expires_in: 3600
    }
  };
}

module.exports = { 
  createLoginFormMessage, 
  handleLoginSubmission, 
  processTokenRequest 
};