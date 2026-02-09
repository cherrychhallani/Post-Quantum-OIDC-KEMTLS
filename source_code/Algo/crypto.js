const fs = require("node:fs");
const path = require("node:path");
const { generateKeyPairSync, sign, verify } = require("crypto"); 

let libPromise = null;

function readBytes(mod, ptr, len) {
  if (!mod.HEAPU8) throw new Error("WASM HEAP not initialized");
  return Buffer.from(mod.HEAPU8.subarray(ptr, ptr + len));
}
function writeBytes(mod, ptr, bytes) {
  if (!mod.HEAPU8) throw new Error("WASM HEAP not initialized");
  mod.HEAPU8.set(bytes, ptr);
}
function toBase64(buf) { return Buffer.from(buf).toString("base64"); }
function fromBase64(str) { return Buffer.from(str, "base64"); }

async function loadOQS() {
  if (libPromise) return libPromise;
  const factory = require("./lib/wrapper.cjs");
  const wasmBinary = fs.readFileSync(path.join(__dirname, "lib", "wrapper.wasm"));
  libPromise = await factory({ wasmBinary, ENVIRONMENT_IS_NODE: true, ENVIRONMENT_IS_WEB: false });
  return libPromise;
}

// === KEM FUNCTIONS ===
async function generateKEMKeyPair() {
  const mod = await loadOQS();
  const alg = "ML-KEM-768";
  const kem = mod.ccall("init_kem", "number", ["string"], [alg]);
  const pkLen = mod.ccall("get_len_pk", "number", ["number"], [kem]);
  const skLen = mod.ccall("get_len_sk", "number", ["number"], [kem]);
  const pkPtr = mod._malloc(pkLen);
  const skPtr = mod._malloc(skLen);
  mod.ccall("generate_keypair", "number", ["number", "number", "number"], [kem, pkPtr, skPtr]);
  const pk = toBase64(readBytes(mod, pkPtr, pkLen));
  const sk = toBase64(readBytes(mod, skPtr, skLen));
  mod._free(pkPtr); mod._free(skPtr); mod.ccall("free_kem", null, ["number"], [kem]);
  return { pk, sk };
}

async function encapsulateSecret(pkBase64) {
  const mod = await loadOQS();
  const alg = "ML-KEM-768";
  const kem = mod.ccall("init_kem", "number", ["string"], [alg]);
  const pk = fromBase64(pkBase64);
  const ctLen = mod.ccall("get_len_ct", "number", ["number"], [kem]);
  const ssLen = mod.ccall("get_len_ss", "number", ["number"], [kem]);
  const ctPtr = mod._malloc(ctLen);
  const ssPtr = mod._malloc(ssLen);
  const pkPtr = mod._malloc(pk.length);
  writeBytes(mod, pkPtr, pk);
  mod.ccall("encap_secret", "number", ["number", "number", "number", "number"], [kem, ctPtr, ssPtr, pkPtr]);
  const ct = toBase64(readBytes(mod, ctPtr, ctLen));
  const ss = readBytes(mod, ssPtr, ssLen);
  mod._free(ctPtr); mod._free(ssPtr); mod._free(pkPtr); mod.ccall("free_kem", null, ["number"], [kem]);
  return { kemCipherText: ct, sharedSecret: ss };
}

async function decapsulateSecret(ctBase64, skBase64) {
  const mod = await loadOQS();
  const alg = "ML-KEM-768";
  const kem = mod.ccall("init_kem", "number", ["string"], [alg]);
  const ct = fromBase64(ctBase64);
  const sk = fromBase64(skBase64);
  const ssLen = mod.ccall("get_len_ss", "number", ["number"], [kem]);
  const ssPtr = mod._malloc(ssLen);
  const ctPtr = mod._malloc(ct.length);
  const skPtr = mod._malloc(sk.length);
  writeBytes(mod, ctPtr, ct);
  writeBytes(mod, skPtr, sk);
  mod.ccall("decap_secret", "number", ["number", "number", "number", "number"], [kem, ssPtr, ctPtr, skPtr]);
  const ss = readBytes(mod, ssPtr, ssLen);
  mod._free(ssPtr); mod._free(ctPtr); mod._free(skPtr); mod.ccall("free_kem", null, ["number"], [kem]);
  return ss;
}

// === SIGNATURES (Native Node.js Ed25519) ===
function generateSignatureKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  return {
    pk: Buffer.from(publicKey).toString("base64"),
    sk: Buffer.from(privateKey).toString("base64")
  };
}

function signMessage(message, skBase64) {
  const privateKey = Buffer.from(skBase64, "base64").toString("utf-8");
  const data = Buffer.from(message);
  const signature = sign(null, data, privateKey);
  return signature.toString("base64");
}

function verifySignature(message, signatureBase64, pkBase64) {
  try {
    const publicKey = Buffer.from(pkBase64, "base64").toString("utf-8");
    const signature = Buffer.from(signatureBase64, "base64");
    const data = Buffer.from(message);
    return verify(null, data, publicKey, signature);
  } catch (e) {
    return false;
  }
}

module.exports = {
  loadOQS,
  generateKEMKeyPair,
  encapsulateSecret,
  decapsulateSecret,
  generateSignatureKeyPair,
  signMessage,
  verifySignature
};