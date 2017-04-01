#include "Group.h"

Group::Group(const string &name, const vector<Host> &hosts) : name(name), hosts(hosts) {}

void Group::addHost(Host host) {
    hosts.push_back(host);
}

const string &Group::getName() const {
    return name;
}

const vector<Host> &Group::getHosts() const {
    return hosts;
}
