#include <bits/stdc++.h>

using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 3) exit(-1);
    auto net1 = argv[1], net2 = argv[2];
    char p1[1024], p2[1024];
    sprintf(p1, "%s-%s-%s", net1, net2, net1);
    sprintf(p2, "%s-%s-%s", net1, net2, net2);
    freopen("link.bash", "w", stdout);
    printf("ip link add %s type veth peer name %s\n", p1, p2);
    printf("ip link set %s netns %s\n", p1, net1);
    printf("ip link set %s netns %s\n", p2, net2);
    printf("ip netns exec %s ip link set %s up\n", net1, p1);
    printf("ip netns exec %s ip addr add [ip here]/24 dev %s\n", net1, p1);
    printf("ip netns exec %s ip link set %s up\n", net2, p2);
    printf("ip netns exec %s ip addr add [ip here]/24 dev %s\n", net2, p2);
    return 0;
}
