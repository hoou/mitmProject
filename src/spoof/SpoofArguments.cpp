#include <getopt.h>
#include <stdexcept>
#include "SpoofArguments.h"

SpoofArguments::SpoofArguments(int argc, char **argv) {
    this->parse(argc, argv);
    if (interface == "" || file == "") {
        //TODO print usage
        throw runtime_error("Usage:");
    }
}

void SpoofArguments::parse(int argc, char **argv) {
    int optionIndex = 0, c = 0;
    const struct option longOptions[] = {
            {"interface", required_argument, 0, 'i'},
            {"file",      required_argument, 0, 'f'}
    };


    while ((c = getopt_long(argc, argv, "i:f:", longOptions, &optionIndex)) != -1) {
        switch (c) {
            case 'i':
                interface = optarg;
                break;
            case 'f':
                file = optarg;
                break;
            default:
                //TODO print usage
                throw runtime_error("Usage:");
        }
    }
}

const string &SpoofArguments::getInterface() const {
    return interface;
}

const string &SpoofArguments::getFile() const {
    return file;
}
