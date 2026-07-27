#include <stddef.h>
#include <stdint.h>

void secure_zeroize(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

void use_secret(uint8_t *p);

void driver(uint8_t *p) {
    use_secret(p);
    secure_zeroize(p, 32);
}
