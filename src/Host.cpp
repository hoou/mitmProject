#include "Host.h"

Host::Host(mac_addr macAddress) : macAddress(macAddress) {}

Host::Host(mac_addr macAddress, set<pair<in_addr, Subnet>> &ipv4addresses, set<in6_addr> &ipv6addresses)
        : macAddress(macAddress), ipv4addresses(ipv4addresses), ipv6addresses(ipv6addresses) {}

void Host::addIpv4Address(in_addr address, in_addr mask) {
    ipv4addresses.insert({address, Subnet(Utils::getSubnetAddress(address, mask), mask)});
}

void Host::addIpv6Address(in6_addr address) {
    ipv6addresses.insert(address);
}

const mac_addr &Host::getMacAddress() const {
    return macAddress;
}

const set<in6_addr> &Host::getIpv6addresses() const {
    return ipv6addresses;
}

ostream &operator<<(ostream &os, const Host &host) {
    os << Utils::formatMacAddress(host.macAddress, six_groups_of_two_hexa_digits_sep_colon);

    if (host.ipv4addresses.size() > 0) {
        for (auto &address : host.ipv4addresses) {
            os << endl << Utils::ipv4ToString(address.first);
        }
    }

    if (host.ipv6addresses.size() > 0) {
        for (auto &address : host.ipv6addresses) {
            os << endl << Utils::ipv6ToString(address);
        }
    }

    return os;
}

const string &Host::getGroupName() const {
    return group;
}

void Host::setGroup(const string &group) {
    Host::group = group;
}

const set<pair<in_addr, Subnet>> &Host::getIpv4addresses() const {
    return ipv4addresses;
}

bool operator<(Subnet a, Subnet b) {
    return Utils::ipv4ToString(a.getAddress()) + " " + Utils::ipv4ToString(a.getMask()) <
           Utils::ipv4ToString(b.getAddress()) + " " + Utils::ipv4ToString(b.getMask());
}

bool operator<(in_addr a, in_addr b) {
    return Utils::ipv4ToString(a) < Utils::ipv4ToString(b);
}

bool operator<(in6_addr a, in6_addr b) {
    return Utils::ipv6ToString(a) < Utils::ipv6ToString(b);
}