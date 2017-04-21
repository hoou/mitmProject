#ifndef PDS_MITM_GROUP_H
#define PDS_MITM_GROUP_H

#include <string>
#include <vector>
#include "Host.h"

using namespace std;

/**
 * Group of network hosts
 */
class Group {
private:
    string name;
    vector<Host> hosts;

public:
    /**
     * Construct group of given name and include given hosts to this group
     * @param name of the group
     * @param hosts belonging to the group
     */
    Group(const string &name, const vector<Host> &hosts);

    void addHost(Host host);

    const string &getName() const;

    const vector<Host> &getHosts() const;

};


#endif //PDS_MITM_GROUP_H
