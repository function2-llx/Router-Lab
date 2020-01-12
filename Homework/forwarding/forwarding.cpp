#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

static uint16_t big(uint8_t* val) { return (uint16_t(val[0]) << 8) + val[1]; }
extern uint16_t get_header_checksum(uint8_t *packet);
extern bool validateIPChecksum(uint8_t *packet, size_t len);

#include <cassert>

bool forward(uint8_t *packet, size_t len) {
    // if (!validateIPChecksum(packet, len)) return 0;
    // packet[8]--;
    // *(uint16_t*)(packet + 10) = get_header_checksum(packet);
    uint16_t old_field = ntohs(*(uint16_t*)(packet + 8));
    packet[8]--;
    uint16_t new_field = ntohs(*(uint16_t*)(packet + 8));
    uint16_t old_csum = ntohs(*(uint16_t*)(packet + 10));
    uint32_t csum = (~old_csum & 0xFFFF) + (~old_field &0xFFFF) + new_field;
    csum = (csum >> 16) + (csum & 0xFFFF);
    csum +=  (csum >> 16);
    csum = ~csum;
    packet[10] = csum >> 8;
    packet[11] = csum & 0xff;
    // assert(validateIPChecksum(packet, len));
    return 1;
}
