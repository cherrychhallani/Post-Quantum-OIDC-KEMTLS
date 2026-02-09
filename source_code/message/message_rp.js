// message_rp.js
const crypto = require("crypto");

const clientId = "rp-001";
const clientSecret = "rp-secret";
const redirectUri = "RP/callback";
const authorizationEndpoint = "IDP_AUTHZ";
const tokenEndpoint = "IDP_TOKEN";

let lastAuthorizationState = null;

function createAuthorizationRequest(scope) {
  if (!scope) throw new Error("scope is required");
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");
  lastAuthorizationState = state;

  return {
    type: "AUTHORIZATION_REQUEST",
    from: "RELYING_PARTY",
    to: "USER_AGENT",
    payload: {
      authorizationEndpoint,
      params: {
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope,
        state,
        nonce
      }
    }
  };
}

function createTokenRequest(code) {
  if (!code) throw new Error("authorization code is required");
  return {
    type: "TOKEN_REQUEST",
    from: "RELYING_PARTY",
    to: "IDENTITY_PROVIDER",
    payload: {
      tokenEndpoint,
      params: {
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri
      }
    }
  };
}

function createLoginSuccessMessage(resource) {
  if (!resource) throw new Error("resource is required");
  return {
    type: "ACCESS_GRANTED",
    from: "RELYING_PARTY",
    to: "USER_AGENT",
    payload: {
      message: "Authentication successful. Access granted.",
      resource,
      timestamp: Date.now()
    }
  };
}

module.exports = {
  clientId,
  clientSecret,
  redirectUri,
  lastAuthorizationState,
  createAuthorizationRequest,
  createTokenRequest,
  createLoginSuccessMessage // <--- ADDED THIS
};