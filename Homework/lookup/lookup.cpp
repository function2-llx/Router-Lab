#include <stdint.h>
#include <cstdlib>
#include <iostream>
#include <utility>
#include <vector>

#include "router.h"

static uint32_t rev_bytes(const uint32_t &val) {
    return (val & 0xff) << 24 | (val & 0xff00) << 8 | (val & 0xff0000) >> 8 |
           (val & 0xff000000) >> 24;
}

struct RouterTable {
    struct node_t {
        node_t *ch[2];
        uint32_t nexthop, if_index;
        bool val;

        node_t() {
            ch[0] = ch[1] = nullptr;
            val = 0;
        }
    };
    node_t *root = nullptr;

    void insert(const RoutingTableEntry &entry) {
        auto addr = rev_bytes(entry.addr);
        if (!root) root = new node_t;
        auto u = root;
        for (int i = 0; i < entry.len; i++) {
            auto &v = u->ch[addr >> (31 - i) & 1];
            if (!v) v = new node_t;
            u = v;
        }
        u->val = 1;
        u->nexthop = entry.nexthop;
        u->if_index = entry.if_index;
    }

    void remove(const RoutingTableEntry &entry) {
        remove(root, 0, rev_bytes(entry.addr), entry.len);
    }

    void remove(node_t *&u, int i, uint32_t addr, uint32_t len) {
        if (!u) return;
        if (i == len)
            u->val = 0;
        else
            remove(u->ch[addr >> (31 - i) & 1], i + 1, addr, len);
        if (!u->ch[0] && !u->ch[1] && !u->val) {
            delete u;
            u = nullptr;
        }
    }

    const node_t *query(uint32_t addr) const {
        addr = rev_bytes(addr);
        if (!root) return nullptr;
        auto u = root;
        const node_t *ret = nullptr;
        for (int i = 31; i >= 0; i--) {
            u = u->ch[addr >> i & 1];
            if (!u) break;
            if (u->val) ret = u;
        }
        return ret;
    }

    void dfs(const node_t* x, uint32_t addr, uint32_t len, std::vector<RoutingTableEntry>& result) const {
        if (!x) return;
        if (x->val) result.push_back(RoutingTableEntry{rev_bytes(addr << (32 - len)), len, x->if_index, x->nexthop});
        dfs(x->ch[0], addr << 1, len + 1, result);
        dfs(x->ch[1], addr << 1 | 1, len + 1, result);
    }
    
    std::vector<RoutingTableEntry> get_all() {
        std::vector<RoutingTableEntry> ret;
        dfs(root, 0, 0, ret);
        return ret;
    }
};
static RouterTable table;

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

void update(bool insert, RoutingTableEntry entry) {
    if (insert)
        table.insert(entry);
    else
        table.remove(entry);
}

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    auto node = table.query(addr);
    if (node) {
        *nexthop = node->nexthop;
        *if_index = node->if_index;
        return true;
    } else
        return false;
}
