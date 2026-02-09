// message_ua.js

/**
 * ===============================
 * USER AGENT STATE
 * ===============================
 */

// Logical session identifier for this UA instance
// Generated once when UA starts
const userAgentSessionId = "ua-session-001";

/**
 * ===============================
 * STEP 1: Protected Resource Request
 * UA -> RP
 * ===============================
 */

/**
 * resource:
 * The protected resource the UA wants to access
 * Example: "PROTECTED_PAGE", "/dashboard"
 */
function createProtectedResourceRequest(resource) {
  if (!resource) {
    throw new Error("resource is required");
  }

  return {
    type: "PROTECTED_RESOURCE_REQUEST",
    from: "USER_AGENT",
    to: "RELYING_PARTY",
    payload: {
      resource,
      userAgentSessionId,
      timestamp: Date.now()
    }
  };
}

module.exports = {
  userAgentSessionId,
  createProtectedResourceRequest
};
