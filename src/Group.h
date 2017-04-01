#ifndef PDS_MITM_GROUP_H
#define PDS_MITM_GROUP_H

#include <string>
#include <vector>
#include "Host.h"

using namespace std;

class Group {
private:
    string name;
    vector<Host> hosts;

public:
    Group(const string &name, const vector<Host> &hosts);

    void addHost(Host host);

    const string &getName() const;

    const vector<Host> &getHosts() const;

};


#endif //PDS_MITM_GROUP_H
