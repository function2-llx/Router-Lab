#include <stdint.h>
#include <cstdlib>
#include <iostream>
#include <utility>
#include <vector>
#include <arpa/inet.h>

#include "router.h"

struct RouterTable {
    struct node_t {
        node_t *ch[2];
        RoutingTableEntry *entry;

        node_t() { 
            ch[0] = ch[1] = nullptr; 
            entry = nullptr;
        }

        void set(const RoutingTableEntry &entry) { this->entry = new RoutingTableEntry(entry); }
        bool has() const { return entry != nullptr; }
        const RoutingTableEntry& get() const { return *entry; }
        RoutingTableEntry& get() { return *entry; }
        void remove() {
            delete entry;
            entry = nullptr;
        }
    };
    node_t *root = nullptr;

    void insert(const RoutingTableEntry &entry) {
        auto addr = ntohl(entry.addr);
        if (!root) root = new node_t;
        auto u = root;
        for (int i = 0; i < entry.len; i++) {
            auto &v = u->ch[addr >> (31 - i) & 1];
            if (!v) v = new node_t;
            u = v;
        }
        u->set(entry);
    }

    void remove(const RoutingTableEntry &entry) {
        remove(root, 0, ntohl(entry.addr), entry.len);
    }

    void recycle(node_t *&u) {
        if (!u->ch[0] && !u->ch[1] && !u->has()) {
            delete u;
            u = nullptr;
        }
    }

    void remove(node_t *&u, int i, uint32_t addr, uint32_t len) {
        if (!u) return;
        if (i == len) {
            u->remove();
        } else {
            remove(u->ch[addr >> (31 - i) & 1], i + 1, addr, len);
        }
        recycle(u);
    }

    const node_t *query(uint32_t addr) const {
        addr = ntohl(addr);
        if (!root) return nullptr;
        auto u = root;
        const node_t *ret = nullptr;
        for (int i = 31; i >= 0; i--) {
            u = u->ch[addr >> i & 1];
            if (!u) break;
            if (u->has()) ret = u;
        }
        return ret;
    }
    const node_t *query(uint32_t addr, uint32_t mask) const {
        addr = ntohl(addr);
        mask = ntohl(mask);
        auto u = root;
        for (int i = 31; i >= 0 && (mask >> i & 1); i--) {
            u = u->ch[addr >> i & 1];
        }
        return u;
    }

    void dfs_all(node_t* x, std::vector<RoutingTableEntry>& result) {
        if (!x) return;
        if (x->has()) {
            auto rte = x->get();
            result.push_back(rte);
            rte.flag = false;
        }
        dfs_all(x->ch[0], result);
        dfs_all(x->ch[1], result);
    }
    
    std::vector<RoutingTableEntry> get_all() {
        std::vector<RoutingTableEntry> ret;
        dfs_all(root, ret);
        return ret;
    }
    
    void dfs_changed(node_t *&x, std::vector<RoutingTableEntry>& result) {
        if (!x) return;
        if (x->has()) {
            auto &rte = x->get();
            if (rte.flag) {
                result.push_back(rte);
                rte.flag = false;
            }
        }
    }

    std::vector<RoutingTableEntry> get_changed() {
        std::vector<RoutingTableEntry> ret;
        dfs_changed(root, ret);
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
    if (insert) {
        table.insert(entry);
    } else {
        table.remove(entry);
    }
}

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    auto node = table.query(addr);
    if (node) {
        const auto &entry = node->get();
        *nexthop = entry.nexthop;
        *if_index = entry.if_index;
        return true;
    } else
        return false;
}

bool query(uint32_t addr, uint32_t mask, RoutingTableEntry& entry) {
    auto u = table.query(addr, mask);
    if (u->has()) {
        entry = u->get();
        return 1;
    } else {
        return 0;
    }
}

std::vector<RoutingTableEntry> get_all_entries() {
    return table.get_all();
}

std::vector<RoutingTableEntry> get_changed_entries() {
    return table.get_changed();
}