#include "router_hal.h"

// configure this to match the output of `ip a`
const char *interfaces[N_IFACE_ON_BOARD] = {
    "r1-r2-r2",
    "r2-r3-r2",
    "eth3",
    "eth4",
};
