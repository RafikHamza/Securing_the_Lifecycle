#include <stdint.h>
#include <stdio.h>
void mlkem_decaps(uint8_t *shared_secret, const uint8_t *ct, const uint8_t *sk);
void secure_zeroize(void *p, unsigned long n);
void handle_decapsulation(const uint8_t *sk, const uint8_t *ct) {
    uint8_t shared_secret[32];
    mlkem_decaps(shared_secret, ct, sk);
    printf("shared secret first byte=%02x", shared_secret[0]);
    secure_zeroize(shared_secret, sizeof shared_secret);
}
