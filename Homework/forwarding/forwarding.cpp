#include <stdint.h>
#include <stdlib.h>

static uint16_t big(uint8_t* val) { return (uint16_t(val[0]) << 8) + val[1]; }
extern uint16_t get_header_checksum(uint8_t *packet);
extern bool validateIPChecksum(uint8_t *packet, size_t len);

#include <cassert>

bool forward(uint8_t *packet, size_t len) {
    // if (!validateIPChecksum(packet, len)) return 0;
    // packet[8]--;
    // *(uint16_t*)(packet + 10) = get_header_checksum(packet);
    uint16_t ttl = (packet[8]--) << 8 | packet[9];
    uint16_t new_ttl = packet[8] << 8 | packet[9];
    uint32_t checksum = packet[10] << 8 | packet[11];
    checksum += ttl + (~new_ttl);
    while (checksum > 0xffff) {
        checksum += checksum >> 16;
        checksum &= 0xffff;
    }
    packet[10] = checksum >> 8;
    packet[11] = checksum & 0xff;
    assert(validateIPChecksum(packet, len));
    return 1;
}
