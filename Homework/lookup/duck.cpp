#include <stdint.h>
#include <cstdlib>
#include <iostream>
#include <utility>
#include "router.h"

static uint32_t rev_bytes(const uint32_t &val) {
    return (val & 0xff) << 24 | (val & 0xff00) << 8 | (val & 0xff0000) >> 8 |
           (val & 0xff000000) >> 24;
}

struct RouterTable {
    struct node_t {
        node_t *ch[2];
        uint32_t nexthop;
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
    }

    const node_t *query(uint32_t addr) {
        addr = rev_bytes(addr);
        if (!root) return nullptr;
        const node_t *ret = root->val ? root : nullptr;
        auto u = root;
        for (int i = 31; i >= 0; i--) {
            u = u->ch[addr >> i & 1];
            if (!u) break;
            if (u->val) ret = u;
        }
        return ret;
    }
};
static RouterTable table;

void init(int n, int q, const RoutingTableEntry *a) {
	for (int i = 0; i < n; i++) table.insert(a[i]);
}

unsigned query(unsigned addr) {
	auto node = table.query(addr);
    return node ? node->nexthop : 0u;
}
