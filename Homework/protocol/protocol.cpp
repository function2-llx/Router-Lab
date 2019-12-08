#include "rip.h"
#include <iostream>
#include <stdint.h>
#include <cassert>
#include <arpa/inet.h>

static uint16_t rev16(const uint8_t *val) { return (uint16_t(val[0]) << 8) + val[1]; }
static uint16_t get16(const uint8_t *val) { return ntohs(rev16(val)); }
static uint32_t rev32(const uint8_t *val) { return (uint32_t(val[0]) << 24) + (uint32_t(val[1]) << 16) + (uint32_t(val[2]) << 8) + val[3]; }
static uint32_t get32(const uint8_t *val) { return ntohl(rev32(val)); }
static constexpr uint16_t RIP_PORT = 0x0802;    // 520

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

// using namespace std;

bool check_subnet(uint32_t mask) {
    mask = ntohl(mask);
    for (int i = 0; i < 32; i++) {
        // mask 必须高位全 1，地位全 0
        if (mask >> i & 1) {
            for (int j = i + 1; j < 32; j++) {
                if (!(mask >> j & 1)) return 0;
            }
            break;
        }
    }
    return 1;
}

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    uint16_t tot_len = rev16(packet + 2);
    int IHL = packet[0] & 0xf;
    if (tot_len > len) return 0;
    len -= IHL * 4;
    packet += IHL * 4;
    uint16_t udp_len = rev16(packet + 4);
    if (udp_len < 8) return 0;
    // 必须来自 rip port
    if (*(uint16_t*)packet != RIP_PORT) return 0;
    uint16_t rip_len = udp_len - 8;
    packet += 8;
    if (rip_len < 4) return 0;
    output->command = packet[0];
    if (output->command != 1 && output->command != 2) return 0;
    uint8_t version = packet[1];
    if (version != 2) return 0;
    if (*(uint16_t*)(packet + 2) != 0) return 0;
    rip_len -= 4;
    packet += 4;
    if (rip_len % 20 != 0) return 0;
    output->numEntries = rip_len / 20;
    if (output->numEntries > RIP_MAX_ENTRY) return 0;

    auto check = [] (rip_command_t cmd, uint16_t family) {
        switch (cmd) {
            case rip_command_t::REQUEST: return family == 0;
            case rip_command_t::RESPONSE: return family == 2;
        }
    };
    for (int i = 0; i < output->numEntries; i++, packet += 20) {
        auto &entry = output->entries[i];
        uint16_t family = rev16(packet);
        if (!check(static_cast<rip_command_t>(output->command), family)) return 0;
        uint16_t tag = rev16(packet + 2);
        if (tag) return 0;
        entry.addr = get32(packet + 4);
        entry.mask = get32(packet + 8);
        if (!check_subnet(entry.mask)) return 0;
        entry.nexthop = get32(packet + 12);
        auto metric = rev32(packet + 16);
        if (metric < 1 || metric > 16) return 0;
        entry.metric = rev32((uint8_t*)&metric);
        assert(metric == rev32((uint8_t*)&entry.metric));
        // entries[i] = entry;
    }
    return 1;
}

uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
    // *(uint16_t*)buffer = htons(rip->command);
    *buffer = rip->command;
    buffer++;
    *buffer = 2;
    buffer++;
    *(uint16_t*)buffer = 0;
    buffer += 2;

    auto get_family_rev = [] (rip_command_t cmd){
        switch (cmd) {
            case rip_command_t::REQUEST: return 0;
            case rip_command_t::RESPONSE: return 0x0200;
        }
    };
    uint16_t family_rev = get_family_rev(static_cast<rip_command_t>(rip->command));
    for (int i = 0; i < rip->numEntries; i++) {
        auto &entry = rip->entries[i];
        *(uint16_t*)buffer = family_rev;
        buffer += 2;
        *(uint16_t*)buffer = 0;
        buffer += 2;
        *(uint32_t*)buffer = entry.addr;
        buffer += 4;
        *(uint32_t*)buffer = entry.mask;
        buffer += 4;
        *(uint32_t*)buffer = entry.nexthop;
        buffer += 4;
        *(uint32_t*)buffer = entry.metric;
        buffer += 4;
    }
    return 4 + rip->numEntries * 20;
}
