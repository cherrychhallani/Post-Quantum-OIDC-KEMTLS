#include <oqs/oqs.h>
#include <emscripten.h>
#include <stdlib.h>
#include <string.h>

// Initialize KEM
EMSCRIPTEN_KEEPALIVE
OQS_KEM *init_kem(const char *method_name) {
    if (!OQS_KEM_alg_is_enabled(method_name)) return NULL;
    return OQS_KEM_new(method_name);
}

// Generate Keypair
EMSCRIPTEN_KEEPALIVE
int generate_keypair(OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key) {
    return OQS_KEM_keypair(kem, public_key, secret_key);
}

// Encapsulate
EMSCRIPTEN_KEEPALIVE
int encap_secret(OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    return OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
}

// Decapsulate
EMSCRIPTEN_KEEPALIVE
int decap_secret(OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    return OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
}

// Cleanup
EMSCRIPTEN_KEEPALIVE
void free_kem(OQS_KEM *kem) {
    OQS_KEM_free(kem);
}

// Helpers for sizes
EMSCRIPTEN_KEEPALIVE
size_t get_len_pk(OQS_KEM *kem) { return kem->length_public_key; }
EMSCRIPTEN_KEEPALIVE
size_t get_len_sk(OQS_KEM *kem) { return kem->length_secret_key; }
EMSCRIPTEN_KEEPALIVE
size_t get_len_ct(OQS_KEM *kem) { return kem->length_ciphertext; }
EMSCRIPTEN_KEEPALIVE
size_t get_len_ss(OQS_KEM *kem) { return kem->length_shared_secret; }



/* =======================================================
 *  DILITHIUM (ML-DSA) — POST-QUANTUM SIGNATURES
 * ======================================================= */

EMSCRIPTEN_KEEPALIVE
OQS_SIG *init_sig(const char *method_name) {
    if (!OQS_SIG_alg_is_enabled(method_name)) return NULL;
    return OQS_SIG_new(method_name);
}

EMSCRIPTEN_KEEPALIVE
int sig_keypair(OQS_SIG *sig,
                uint8_t *public_key,
                uint8_t *secret_key) {
    return OQS_SIG_keypair(sig, public_key, secret_key);
}

EMSCRIPTEN_KEEPALIVE
int sig_sign(OQS_SIG *sig,
             uint8_t *signature,
             size_t *sig_len,
             const uint8_t *message,
             size_t message_len,
             const uint8_t *secret_key) {
    return OQS_SIG_sign(sig,
                        signature,
                        sig_len,
                        message,
                        message_len,
                        secret_key);
}

EMSCRIPTEN_KEEPALIVE
int sig_verify(OQS_SIG *sig,
               const uint8_t *message,
               size_t message_len,
               const uint8_t *signature,
               size_t sig_len,
               const uint8_t *public_key) {
    return OQS_SIG_verify(sig,
                          message,
                          message_len,
                          signature,
                          sig_len,
                          public_key);
}

EMSCRIPTEN_KEEPALIVE
void free_sig(OQS_SIG *sig) {
    OQS_SIG_free(sig);
}

/* ---- Size helpers ---- */
EMSCRIPTEN_KEEPALIVE size_t sig_len_pk(OQS_SIG *sig) { return sig->length_public_key; }
EMSCRIPTEN_KEEPALIVE size_t sig_len_sk(OQS_SIG *sig) { return sig->length_secret_key; }
EMSCRIPTEN_KEEPALIVE size_t sig_len_sig(OQS_SIG *sig) { return sig->length_signature; }


