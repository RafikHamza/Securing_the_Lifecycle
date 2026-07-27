#include <stdint.h>
#include <stddef.h>
void mlkem_decaps(uint8_t *shared_secret, const uint8_t *ct, const uint8_t *sk);
void derive_session_key(uint8_t *session_key, const uint8_t *shared_secret);
void tls_send_encrypted(const uint8_t *session_key, const char *msg, size_t len);
void secure_zeroize(void *p, size_t n);

void handle_decapsulation(const uint8_t *sk, const uint8_t *ct) {
    uint8_t shared_secret[32];
    uint8_t session_key[32];
    mlkem_decaps(shared_secret, ct, sk);
    derive_session_key(session_key, shared_secret);
    tls_send_encrypted(session_key, "ok", 2);
    secure_zeroize(shared_secret, sizeof shared_secret);
    /* BUG: session_key remains live after encrypted use. */
}
