#include <limits>
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <arpa/inet.h>

// static uint16_t big(uint8_t* val) { return (uint16_t(val[0]) << 8) + val[1]; }

uint16_t get_header_checksum(uint8_t *packet) {
    uint32_t checksum = 0;
    uint8_t IHL = packet[0] & 0xf;
    for (size_t i = 0; i < IHL * 4; i += 2) {
        if (i == 10) continue;
        checksum += ntohs(*(uint16_t*)(packet + i));
        checksum = (uint16_t(checksum) & 0xffff) + (checksum >> 16);
    }
    // while (checksum > 0xffff)
    return htons(~checksum);
}

bool validateIPChecksum(uint8_t *packet, size_t len) {
    auto checksum = get_header_checksum(packet);
    // printf("checksum: %x %x\n", checksum, *(uint16_t*)(packet + 10));
    return *(uint16_t*)(packet + 10) == get_header_checksum(packet);
}
