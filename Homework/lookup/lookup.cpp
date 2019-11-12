#include <stdint.h>
#include <cstdlib>
#include <utility>
#include <iostream>
#include "router.h"

struct Trie {
    struct node_t {
        node_t *ch[2];
        RoutingTableEntry *entry;

        node_t() {
            ch[0] = ch[1] = nullptr;
            entry = nullptr;
        }
    };
    node_t *root = nullptr;

    void insert(RoutingTableEntry &&entry) {
        if (!root) root = new node_t;
        auto u = root;
        for (int i = 0; i < entry.len; i++) {
            auto &v = u->ch[entry.addr >> i & 1];
            if (!v) v = new node_t;
            u = v;
        }
        delete u->entry;
        u->entry = new RoutingTableEntry(entry);
    }

    void remove(const RoutingTableEntry &entry) {
        remove(root, 0, entry.addr, entry.len);
    }

    void remove(node_t *&u, int i, uint32_t addr, uint32_t len) {
        if (!u) return;
        if (i == len) {
            delete u->entry;
            u->entry = nullptr;
        } else {
            remove(u->ch[addr >> i & 1], i + 1, addr, len);
        }
        if (!u->ch[0] && !u->ch[1] && !u->entry) {
            delete u;
            u = nullptr;
        }
    }

    const RoutingTableEntry *query(uint32_t addr) {
        if (!root) return nullptr;
        auto u = root;
        const RoutingTableEntry *ret = nullptr;
        for (int i = 0; i < 32; i++) {
            u = u->ch[addr >> i & 1];
            if (!u) break;
            if (u->entry) {
                ret = u->entry;
            }
        }
        return ret;
    }
};
static Trie trie;

void update(bool insert, RoutingTableEntry entry) {
    if (insert)
        trie.insert(std::move(entry));
    else
        trie.remove(entry);
}

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    auto entry = trie.query(addr);
    if (entry) {
        *nexthop = entry->nexthop;
        *if_index = entry->if_index;
        return true;
    } else {
        return false;
    }
}
