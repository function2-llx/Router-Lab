#include <limits>
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <iostream>

static uint16_t big(uint8_t* val) { return (uint16_t(val[0]) << 8) + val[1]; }

bool validateIPChecksum(uint8_t *packet, size_t len) {
    using std::cerr;
    using std::endl;
    uint32_t checksum = 0;
    uint8_t IHL = packet[0] & 0xf;
    for (size_t i = 0; i < IHL * 4; i += 2) {
        if (i == 10) continue;
        checksum += big(packet + i);
    }
    while (checksum > 0xffff)
        checksum = (uint16_t(checksum) & 0xffff) + (checksum >> 16);
    uint16_t actual = ~big(packet + 10);
    return checksum == actual;
}
