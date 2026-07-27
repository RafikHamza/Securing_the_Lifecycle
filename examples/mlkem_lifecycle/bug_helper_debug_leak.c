#include <stdint.h>
#include <stdio.h>
void mlkem_decaps(uint8_t *shared_secret, const uint8_t *ct, const uint8_t *sk);
void secure_zeroize(void *p, unsigned long n);
static void debug_dump(uint8_t *p) { printf("%02x", p[0]); }
void handle_decapsulation(const uint8_t *sk, const uint8_t *ct) {
    uint8_t shared_secret[32];
    uint8_t *alias = shared_secret;
    mlkem_decaps(shared_secret, ct, sk);
    debug_dump(alias);
    secure_zeroize(shared_secret, sizeof shared_secret);
}
