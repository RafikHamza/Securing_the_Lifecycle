#include <stdint.h>
void mlkem_decaps(uint8_t *shared_secret, const uint8_t *ct, const uint8_t *sk);
void secure_zeroize(void *p, unsigned long n);
void uart_write_bytes(int uart, const void *data, unsigned long len);
void handle_decapsulation(const uint8_t *sk, const uint8_t *ct) {
    uint8_t shared_secret[32];
    mlkem_decaps(shared_secret, ct, sk);
    uart_write_bytes(0, shared_secret, sizeof shared_secret);
    secure_zeroize(shared_secret, sizeof shared_secret);
}
