#include <stdint.h>
#include <sys/socket.h>
void mlkem_decaps(uint8_t *shared_secret, const uint8_t *ct, const uint8_t *sk);
void secure_zeroize(void *p, unsigned long n);
void handle_decapsulation(int fd, const uint8_t *sk, const uint8_t *ct) {
    uint8_t shared_secret[32];
    mlkem_decaps(shared_secret, ct, sk);
    send(fd, shared_secret, sizeof shared_secret, 0);
    secure_zeroize(shared_secret, sizeof shared_secret);
}
