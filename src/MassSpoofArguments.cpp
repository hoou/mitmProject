#include <getopt.h>
#include <sstream>
#include <iostream>
#include "MassSpoofArguments.h"

MassSpoofArguments::MassSpoofArguments(int argc, char **argv) {
    parse(argc, argv);
    validate();
}

void MassSpoofArguments::parse(int argc, char **argv) {
    int optionIndex = 0, c = 0;

    const struct option longOptions[] = {
            {"interface", required_argument, 0, 'i'},
            {"time",      required_argument, 0, 't'},
            {"protocol",  required_argument, 0, 'p'},
            {"file",      required_argument, 0, 'f'},
            {NULL, 0,                        0, 0}
    };

    while ((c = getopt_long_only(argc, argv, "", longOptions, &optionIndex)) != -1) {
        switch (c) {
            case 'i':
                interface = optarg;
                iFlag = true;
                break;
            case 't':
                stringstream(optarg) >> time;
                tFlag = true;
                break;
            case 'p':
                protocol = optarg;
                if (protocol == "arp" || protocol == "ndp") {
                    pFlag = true;
                } else {
                    throw InvalidArgumentsException("protocol must be \"arp\" or \"ndp\"");
                }
                break;
            case 'f':
                filename = optarg;
                fFlag = true;
                break;
            default:
                throw InvalidArgumentsException();
        }
    }

}

void MassSpoofArguments::validate() {
    if (!iFlag || !tFlag || !pFlag || !fFlag) {
        throw InvalidArgumentsException("missing required arguments");
    }
}

void MassSpoofArguments::printUsage() {
    cout << "Usage: ./pds-massspoof -i interface -t sec -p protocol -f file" << endl;
    cout << "Required arguments:" << endl;
    cout << "interface - name of network interface where spoof will be performed" << endl;
    cout << "sec - interval in milliseconds for sending ARP/NDP packets that causes cache poisoning" << endl;
    cout << "protocol - arp or ndp - which protocol to use to poison cache" << endl;
    cout << "file - input file with marked victim pairs" << endl;
}

const string &MassSpoofArguments::getInterface() const {
    return interface;
}

unsigned long long int MassSpoofArguments::getTime() const {
    return time;
}

const string &MassSpoofArguments::getProtocol() const {
    return protocol;
}

const string &MassSpoofArguments::getFilename() const {
    return filename;
}
