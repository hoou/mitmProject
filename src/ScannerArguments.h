#ifndef PDS_MITM_SCANNERARGUMENTS_H
#define PDS_MITM_SCANNERARGUMENTS_H

#include <string>

using namespace std;

class ScannerArguments {
private:
    string interface = "";
    string file = "";

    void parse(int argc, char **argv);

public:

    const string &getInterface() const;

    const string &getFile() const;

    ScannerArguments(int argc, char **argv);
};


#endif //PDS_MITM_SCANNERARGUMENTS_H
