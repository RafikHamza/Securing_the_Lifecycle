#include <stdint.h>
void mlkem_decaps(uint8_t *shared_secret, const uint8_t *ct, const uint8_t *sk);
void secure_zeroize(void *p, unsigned long n);
void nvs_set_blob(void *h, const char *key, const void *value, unsigned long len);
void handle_decapsulation(void *h, const uint8_t *sk, const uint8_t *ct) {
    uint8_t shared_secret[32];
    mlkem_decaps(shared_secret, ct, sk);
    nvs_set_blob(h, "ss", shared_secret, sizeof shared_secret);
    secure_zeroize(shared_secret, sizeof shared_secret);
}
