#include <stdio.h>
#include <oqs/oqs.h>

int main(void) {
    printf("=== KEM Algorithms ===\n");
    size_t kem_count = OQS_KEM_alg_count();
    for (size_t i = 0; i < kem_count; i++) {
        const char *alg_name = OQS_KEM_alg_identifier(i);
        OQS_KEM *kem = OQS_KEM_new(alg_name);
        if (kem != NULL) {
            printf("Name: %s\n", alg_name);
            printf("  Public key length: %zu\n", kem->length_public_key);
            printf("  Secret key length: %zu\n", kem->length_secret_key);
            printf("  Ciphertext length: %zu\n", kem->length_ciphertext);
            OQS_KEM_free(kem);
        }
    }

    printf("\n=== SIG Algorithms ===\n");
    size_t sig_count = OQS_SIG_alg_count();
    for (size_t i = 0; i < sig_count; i++) {
        const char *sig_alg = OQS_SIG_alg_identifier(i);
        OQS_SIG *sig = OQS_SIG_new(sig_alg);
        if (sig != NULL) {
            printf("Name: %s\n", sig_alg);
            printf("  Public key length: %zu\n", sig->length_public_key);
            printf("  Secret key length: %zu\n", sig->length_secret_key);
            printf("  Signature length: %zu\n", sig->length_signature);
            OQS_SIG_free(sig);
        }
    }
    return 0;
}
