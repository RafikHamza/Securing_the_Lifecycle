#include <stddef.h>
#include <stdint.h>

uint8_t *derive_session_key(uint8_t *shared_secret);
void aead_init(uint8_t *session_key);
void secure_zeroize(uint8_t *buffer);
void net_send(uint8_t *buffer);


void session_setup(uint8_t *shared_secret) {
    uint8_t *session_key = derive_session_key(shared_secret);
    net_send(shared_secret);
    aead_init(session_key);
    secure_zeroize(shared_secret);
}
