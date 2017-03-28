#ifndef PDS_MITM_SPOOFPARSER_H
#define PDS_MITM_SPOOFPARSER_H

using namespace std;

class SpoofArguments {
private:
    string interface = "";
    string file = "";

    void parse(int argc, char **argv);

public:

    const string &getInterface() const;

    const string &getFile() const;

    SpoofArguments(int argc, char **argv);
};


#endif //PDS_MITM_SPOOFPARSER_H
