#include <string.h>
#include <stdint.h>

void bad_clear(uint8_t *p) {
    memset(p, 0, 32);
}
