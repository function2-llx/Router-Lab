#include <stdint.h>
#include <stdio.h>
#include <vector>
#include <stdlib.h>
#include <string.h>
#include <algorithm>

#include "rip.h"
#include "router.h"
#include "router_hal.h"
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
extern bool validateIPChecksum(uint8_t *packet, size_t len);
/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
extern void update(bool insert, RoutingTableEntry entry);
/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool query(uint32_t addr, uint32_t mask, RoutingTableEntry& entry);
/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
extern bool forward(uint8_t *packet, size_t len);
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
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
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
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

// 通过计算得到 checksum，大端序
extern uint16_t get_header_checksum(uint8_t *packet);
// 返回全部路由表项
extern std::vector<RoutingTableEntry> get_all_entries();
// 返回改变了的路由表项
extern std::vector<RoutingTableEntry> get_changed_entries();

static uint16_t rev16(const uint8_t *val) { return (uint16_t(val[0]) << 8) + val[1]; }
static uint16_t get16(const uint8_t *val) { return ntohs(rev16(val)); }
static uint32_t rev32(const uint8_t *val) { return (uint32_t(val[0]) << 24) + (uint32_t(val[1]) << 16) + (uint32_t(val[2]) << 8) + val[3]; }
static uint32_t get32(const uint8_t *val) { return ntohl(rev32(val)); }

static uint8_t packet[2048];
static uint8_t output[2048];
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
static in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a,
                                    0x0103000a};

#include <assert.h>

// 根据 len 返回大端序的掩码
static uint32_t get_mask(int len) { 
    return htonl(((1ll << len) - 1) << (32 - len)); 
}
// 根据 mask 返回小端序的 len
static uint32_t get_len(uint32_t mask) {
    mask = ntohl(mask);
    for (int i = 31; i >= 0; i--) {
        if (!(mask >> i & 1)) return 31 - i;
    }
    return 32;
}

// 224.0.0.9
static constexpr uint32_t RIP_MULTI_ADDR = 0x090000e0;
static constexpr uint16_t RIP_PORT = 0x0802;    // 520

// 从 if_index 端口向 dst_addr 发送路由表项
static void make_response(int if_index, in_addr_t dst_addr, const std::vector<RoutingTableEntry>& entries) {
    if (entries.empty()) return;
    macaddr_t dst_mac;
    if (HAL_ArpGetMacAddress(if_index, dst_addr, dst_mac) == 0) {
        output[0] = 0x45;                                   // ip: version, ihl
        output[1] = 0;                                      // ip: TOS(DSCP/ECN)=0
        *(uint16_t*)(output + 4) = 0;                       // ip: id = 0
        *(uint16_t*)(output + 6) = 0;                       // ip: FLAGS/OFF=0
        output[8] = 1;                                      // ip: ttl
        output[9] = 0x11;                                   // ip: protocol = udp
        *(in_addr_t*)(output + 12) = addrs[if_index];       // ip: src addr
        *(in_addr_t*)(output + 16) = dst_addr;              // ip: dst addr
        *(uint16_t*)(output + 20) = RIP_PORT;               // udp: src port
        *(uint16_t*)(output + 22) = RIP_PORT;               // udp: dst port
        *(uint16_t*)(output + 26) = htons(0);               // udp: checksum = 0
        for (unsigned i = 0; i < entries.size(); i += RIP_MAX_ENTRY) {
            RipPacket rip;
            rip.command = rip_command_t::RESPONSE;
            rip.numEntries = std::min(size_t(RIP_MAX_ENTRY), entries.size() - i);
            for (unsigned j = 0; j < rip.numEntries; j++) {
                auto &rte = entries[i + j];
                auto &entry = rip.entries[j];
                entry.addr = rte.addr;
                entry.metric = rte.metric;
                entry.mask = get_mask(rte.len);
                entry.nexthop = rte.nexthop;
            }
            auto rip_len = assemble(&rip, output + 20 + 8);
            *(uint16_t*)(output + 24) = htons(8 + rip_len);                     // udp: length = 8 + rip_len
            *(uint16_t*)(output + 2) = htons(20 + 8 + rip_len);                 // ip: total length
            *(uint16_t*)(output + 10) = get_header_checksum(output);            // ip: checksum
            HAL_SendIPPacket(if_index, output, 20 + 8 + rip_len, dst_mac);
        }
    }
}

// 组播发送路由表
static void multicast(const std::vector<RoutingTableEntry>& entries, bool split_horizon = false) {
    printf("multicast size: %lu\n", entries.size());
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
        if (!split_horizon) {
            make_response(i, RIP_MULTI_ADDR, entries);
        } else {
            std::vector<RoutingTableEntry> cur;
            for (auto &entry: entries) {
                if (entry.if_index != i) cur.push_back(entry);
            }
            make_response(i, RIP_MULTI_ADDR, cur);
        }
    }
}

static void multicast_request() {
    RipPacket rp;
    rp.command = rip_command_t::REQUEST;
    rp.numEntries = 1;
    rp.entries[0].metric = 16;
    for (int if_index = 0; if_index < N_IFACE_ON_BOARD; if_index++) {
        macaddr_t dst_mac;
        if (HAL_ArpGetMacAddress(if_index, RIP_MULTI_ADDR, dst_mac) == 0) {
            output[0] = 0x45;                                   // ip: version, ihl
            output[1] = 0;                                      // ip: TOS(DSCP/ECN)=0
            *(uint16_t*)(output + 4) = 0;                       // ip: id = 0
            *(uint16_t*)(output + 6) = 0;                       // ip: FLAGS/OFF=0
            output[9] = 0x11;                                   // ip: protocol = udp
            *(in_addr_t*)(output + 12) = addrs[if_index];       // ip: src addr
            *(in_addr_t*)(output + 16) = RIP_MULTI_ADDR;              // ip: dst addr
            *(uint16_t*)(output + 20) = RIP_PORT;               // udp: src port
            *(uint16_t*)(output + 22) = RIP_PORT;               // udp: dst port
            *(uint16_t*)(output + 26) = htons(0);               // udp: checksum = 0
            auto rip_len = assemble(&rp, output + 20 + 8);
            *(uint16_t*)(output + 24) = htons(8 + rip_len);                      // udp: length = 8
            *(uint16_t*)(output + 2) = htons(20 + 8 + rip_len);                 // ip: total length
            *(uint16_t*)(output + 10) = get_header_checksum(output);     // ip: checksum
            HAL_SendIPPacket(if_index, output, 20 + 8 + rip_len, dst_mac);
        }
    }
}

#include <random>

std::mt19937 rng(time(0));

int main(int argc, char *argv[]) {
    // 0a.
    int res = HAL_Init(1, addrs);
    if (res < 0) {
        return res;
    }

    // 0b. Add direct routes
    for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
        RoutingTableEntry entry = {
            .addr = addrs[i] & 0x00FFFFFF, // big endian
            .len = 24,        // small endian
            .if_index = i,    // small endian
            .nexthop = 0      // big endian, means direct
        };
        update(true, entry);
    }

    bool triggered = 0;
    uint64_t triggered_last = 0, triggered_timer = 0;
    uint64_t last_time = 0;
    uint64_t regular_timer = 5;
    while (1) {
        uint64_t time = HAL_GetTicks();
        if (time > last_time + regular_timer * 1000) {
            // What to do? 
            // TODO: send complete routing table to every interface
            // ref. RFC2453 3.8
            multicast(get_all_entries());
            printf("regular %lus Timer\n", regular_timer);
            last_time = time;
            triggered = false;
            triggered_timer = 0;
        } else if (triggered && time - triggered_last > triggered_timer) {
            printf("triggered udpate\n");
            auto entries = get_changed_entries();
            multicast(entries);
            for (auto &entry: entries) {
                if (entry.metric == 16) update(false, entry);
            }
            triggered_last = time;
            triggered_timer = rng() % 4000 + 1000;  // between 1s and 5s
            triggered = false;
        }

        int mask = (1 << N_IFACE_ON_BOARD) - 1;
        macaddr_t src_mac;
        macaddr_t dst_mac;
        int if_index;
        res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac, 1000, &if_index);
        if (res == HAL_ERR_EOF) {
            break;
        } else if (res < 0) {
            return res;
        } else if (res == 0) {
            // Timeout
            continue;
        } else if (res > sizeof(packet)) {
            // packet is truncated, ignore it
            continue;
        }

        // 1. validate
        if (!validateIPChecksum(packet, res)) {
            printf("Invalid IP Checksum\n");
            continue;
        }
        in_addr_t src_addr, dst_addr;
        // TODO: extract src_addr and dst_addr from packet
        // big endian
        src_addr = *(uint32_t*)(packet + 12);
        dst_addr = *(uint32_t*)(packet + 16);

        // 2. check whether dst is me
        bool dst_is_me = false;
        for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
            if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
                dst_is_me = true;
                break;
            }
        }
        // TODO: Handle rip multicast address(224.0.0.9)?
        if (dst_addr == RIP_MULTI_ADDR) dst_is_me = true;

        if (dst_is_me) {
            // 3a.1
            RipPacket rip;
            // check and validate
            if (disassemble(packet, res, &rip)) {
                if (rip.command == rip_command_t::REQUEST) {
                    // 3a.3 request, ref. RFC2453 3.9.1
                    // only need to respond to whole table requests in the lab
                    make_response(if_index, src_addr, get_all_entries());
                    printf("response to request\n");
                } else {
                    // 3a.2 response, ref. RFC2453 3.9.2
                    // update routing table
                    // new metric = ?
                    // update metric, if_index, nexthop
                    // what is missing from RoutingTableEntry?
                    // TODO: use query and update
                    // triggered updates? ref. RFC2453 3.10.1
                    printf("received response\n");
                    uint32_t nexthop, metric, addr;
                    for (int i = 0; i < rip.numEntries; i++) {
                        auto &re = rip.entries[i];
                        uint32_t new_metric = htonl(std::min(ntohl(re.metric) + 1, 16u));
                        printf("new metric: %u\n", ntohl(new_metric));
                        RoutingTableEntry rte;
                        if (!query(re.addr, re.mask, rte)) {
                            // there is no point in adding a route which is unusable
                            if (ntohl(new_metric) < 16) {
                                printf("insert new route table entry\n");
                                rte.addr = re.addr;
                                rte.len = get_len(re.mask);
                                printf("new len: %d\n", rte.len);
                                rte.if_index = if_index;
                                rte.nexthop = src_addr;
                                rte.metric = new_metric;
                                rte.flag = true;
                                triggered = true;
                                update(true, rte);
                            }
                        } else {
                            if (rte.nexthop == src_addr && rte.metric != new_metric || rte.metric > new_metric) {
                                printf("update route table entry\n");
                                rte.metric = new_metric;
                                rte.nexthop = src_addr;
                                rte.if_index = if_index;
                                rte.flag = true;
                                triggered = true;
                                update(true, rte);
                            }
                        }
                    }
                }
            }
        } else {
            // 3b.1 dst is not me
            // forward
            // beware of endianness
            uint32_t nexthop, dest_if;
            if (query(dst_addr, &nexthop, &dest_if)) {
                // found
                // direct routing
                if (nexthop == 0) {
                    nexthop = dst_addr;
                }
                macaddr_t dest_mac;
                if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
                    // found
                    memcpy(output, packet, res);
                    // update ttl and checksum
                    if (forward(output, res)) {
                        // TODO: you might want to check ttl=0 case
                        uint8_t ttl = output[8];
                        if (ttl) {
                            HAL_SendIPPacket(dest_if, output, res, dest_mac);
                            printf("forward packet, src: %x, dst: %x\n", ntohl(src_addr), ntohl(dst_addr));
                        } else {
                            printf("ttl hit zero, drop packet\n");
                        }
                    }
                } else {
                    // not found
                    // you can drop it
                    printf("ARP not found for %x\n", nexthop);
                }
            } else {
                // not found
                // optionally you can send ICMP Host Unreachable
                // TODO: send request
                multicast_request();
                printf("IP not found for %x\n", src_addr);
            }
        }
    }
    return 0;
}
