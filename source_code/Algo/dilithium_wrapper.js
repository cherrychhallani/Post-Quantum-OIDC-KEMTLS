// Algo/dilithium_wrapper.js
const DilithiumLoader = require('dilithium-crystals-js');

// NIST Security Level 3 (Recommended)
const DILITHIUM_LEVEL = 3; 

let dilithium = null;

// Initialize the WASM module
async function getDilithium() {
    if (!dilithium) {
        dilithium = await DilithiumLoader;
    }
    return dilithium;
}

// 1. Generate Keys
async function generateDilithiumKeyPair() {
    const d = await getDilithium();
    
    // generateKeys(level) returns { publicKey, privateKey } as Uint8Array
    const keyPair = d.generateKeys(DILITHIUM_LEVEL);
    
    // Convert to Base64 for easy transport in JSON
    const pk = Buffer.from(keyPair.publicKey).toString('base64');
    const sk = Buffer.from(keyPair.privateKey).toString('base64');
    
    return { pk, sk };
}

// 2. Sign a Message
async function signWithDilithium(message, skBase64) {
    const d = await getDilithium();
    const sk = Buffer.from(skBase64, 'base64');
    const msg = Buffer.from(message); // Ensure message is a Buffer
    
    // sign returns { signature, signatureLength }
    const signResult = d.sign(msg, sk, DILITHIUM_LEVEL);
    
    return Buffer.from(signResult.signature).toString('base64');
}

// 3. Verify a Signature
async function verifyDilithium(message, signatureBase64, pkBase64) {
    const d = await getDilithium();
    const pk = Buffer.from(pkBase64, 'base64');
    const signature = Buffer.from(signatureBase64, 'base64');
    const msg = Buffer.from(message);
    
    // verify returns an object { result: number, ... }
    // In this library, result === 0 means VALID (Standard C return code)
    const verification = d.verify(signature, msg, pk, DILITHIUM_LEVEL);
    
    return verification.result === 0;
}

module.exports = {
    generateDilithiumKeyPair,
    signWithDilithium,
    verifyDilithium
};