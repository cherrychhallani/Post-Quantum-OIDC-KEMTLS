import { generateKEMKeyPair, encapsulateSecret, decapsulateSecret } from '../Algo/crypto.js';
import crypto from 'crypto';

export async function serverStaticKeyGen() {
  const keys = await generateKEMKeyPair();
  return { pk_s: keys.pk, sk_s: keys.sk };
}

export async function clientEphemeralKeyGen() {
  const keys = await generateKEMKeyPair();
  return { pk_e: keys.pk, sk_e: keys.sk };
}

export async function kemEncapsulate(pk_e) {
  const result = await encapsulateSecret(pk_e);
  return { ss_e: result.sharedSecret, ct_e: result.kemCipherText };
}

export async function kemDecapsulate(ct, sk) {
  return await decapsulateSecret(ct, sk);
}

export async function kemEncapsulateToServer(pk_s) {
  const result = await encapsulateSecret(pk_s);
  return { ss_s: result.sharedSecret, cts: result.kemCipherText };
}


/* HKDF for KEMTLS */
export function deriveFinalKeys(ss_e, ss_s, role) {
  const ikm = Buffer.concat([Buffer.from(ss_e), Buffer.from(ss_s)]);
  return crypto.hkdfSync(
    'sha256',
    Buffer.alloc(0),        // salt (can be transcript hash later)
    ikm,
    Buffer.from(`KEMTLS-${role}`),
    32
  );
}

/* Simulated certificate verification */
export function verifyServerCertificate(pk_s) {
  // In real TLS: verify signature chain
  // In KEMTLS projects: proving possession of sk_s is sufficient
  return pk_s && pk_s.length > 0;
}