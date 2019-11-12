#include "rip.h"
#include <iostream>
#include <stdint.h>
#include <cassert>
#include <arpa/inet.h>

uint16_t rev16(const uint8_t *val) { return (uint16_t(val[0]) << 8) + val[1]; }
uint16_t get16(const uint8_t *val) { return ntohs(rev16(val)); }
uint32_t rev32(const uint8_t *val) { return (uint32_t(val[0]) << 24) + (uint32_t(val[1]) << 16) + (uint32_t(val[2]) << 8) + val[3]; }
uint32_t get32(const uint8_t *val) { return ntohl(rev32(val)); }

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */

// using namespace std;

enum rip_command_t {
    REQUEST = 1,
    RESPONSE = 2,
};

bool check_subnet(uint32_t mask) {
    mask = ntohl(mask);
    for (int i = 0; i < 32; i++) {
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
    // cerr << "udp len: " << udp_len << endl;
    if (udp_len < 8) return 0;
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

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
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
