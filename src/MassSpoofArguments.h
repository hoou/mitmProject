#ifndef PDS_MITM_MASSSPOOFARGUMENTS_H
#define PDS_MITM_MASSSPOOFARGUMENTS_H


#include <netinet/in.h>
#include "Arguments.h"

class MassSpoofArguments : public Arguments {
private:
    string interface;
    unsigned long long time;
    string protocol;
    string filename;

    bool iFlag = false;
    bool tFlag = false;
    bool pFlag = false;
    bool fFlag = false;

    void parse(int argc, char **argv) override;

    void validate() override;

public:
    MassSpoofArguments(int argc, char **argv);

    static void printUsage();

    const string &getInterface() const;

    unsigned long long int getTime() const;

    const string &getProtocol() const;

    const string &getFilename() const;
};


#endif //PDS_MITM_MASSSPOOFARGUMENTS_H
