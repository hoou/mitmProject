#ifndef PDS_MITM_SCANNERARGUMENTS_H
#define PDS_MITM_SCANNERARGUMENTS_H

#include <string>
#include "Arguments.h"

using namespace std;

class ScannerArguments : public Arguments {
private:
    string interface = "";
    string file = "";

    void parse(int argc, char **argv) override;

    void validate() override;

public:

    ScannerArguments(int argc, char **argv);

    const string &getInterface() const;

    const string &getFile() const;

    static void printUsage();
};


#endif //PDS_MITM_SCANNERARGUMENTS_H
