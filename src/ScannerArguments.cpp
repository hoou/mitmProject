#include <getopt.h>
#include <stdexcept>
#include <iostream>
#include "ScannerArguments.h"

ScannerArguments::ScannerArguments(int argc, char **argv) {
    parse(argc, argv);
    validate();
}

void ScannerArguments::parse(int argc, char **argv) {
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
                throw InvalidArgumentsException();
        }
    }
}

void ScannerArguments::validate() {
    if (interface == "" || file == "") {
        throw InvalidArgumentsException("missing required arguments");
    }
}

const string &ScannerArguments::getInterface() const {
    return interface;
}

const string &ScannerArguments::getFile() const {
    return file;
}

void ScannerArguments::printUsage() {
    cout << "Usage: ./pds-scanner -i interface -f file" << endl;
    cout << "Required arguments:" << endl;
    cout << "interface - name of network interface, where scan will be performed" << endl;
    cout << "file - output filename with found hosts" << endl;
}

void ScannerArguments::printInterceptUsage() {
    cout << "Usage: ./pds-intercept -i interface -f file" << endl;
    cout << "Required arguments:" << endl;
    cout << "interface - name of network interface, where intercept will be performed" << endl;
    cout << "file - input filename with marked victims" << endl;
}
