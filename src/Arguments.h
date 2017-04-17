#ifndef PDS_MITM_ARGUMENTS_H
#define PDS_MITM_ARGUMENTS_H

#include <stdexcept>

using namespace std;

class InvalidArgumentsException : public runtime_error {
public:
    InvalidArgumentsException();

    InvalidArgumentsException(const string &__arg);
};


class Arguments {
private:
    virtual void parse(int argc, char **argv) = 0;

    virtual void validate() = 0;
};


#endif //PDS_MITM_ARGUMENTS_H
