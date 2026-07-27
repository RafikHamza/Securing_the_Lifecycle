#include <stdint.h>
void mlkem_decaps(uint8_t *shared_secret, const uint8_t *ct, const uint8_t *sk);
void derive_session_key(uint8_t *session_key, const uint8_t *shared_secret);
void secure_zeroize(void *p, unsigned long n);
void handle_decapsulation(const uint8_t *sk, const uint8_t *ct) {
    uint8_t shared_secret[32];
    uint8_t session_key[32];
    mlkem_decaps(shared_secret, ct, sk);
    secure_zeroize(shared_secret, sizeof shared_secret);
    derive_session_key(session_key, shared_secret);
}
