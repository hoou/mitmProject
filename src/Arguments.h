#ifndef PDS_MITM_ARGUMENTPARSER_H
#define PDS_MITM_ARGUMENTPARSER_H

using namespace std;

class Arguments {
private:
    string interface = "";
    string file = "";

    void parse(int argc, char **argv);

public:

    const string &getInterface() const;

    const string &getFile() const;

    Arguments(int argc, char **argv);
};


#endif //PDS_MITM_ARGUMENTPARSER_H
