#include <cstdlib>
#include <scanner/ScannerArguments.h>
#include <iostream>
#include "SpoofArguments.h"

int main(int argc, char **argv) {
    try {
        SpoofArguments arguments(argc, argv);

        cout << "interface: " << arguments.getInterface() << endl;
        cout << "time: " << arguments.getTime() << endl;
        cout << "protocol: " << arguments.getProtocol() << endl;
        cout << "victim 1 ip: "
             << (arguments.isVictim1Ipv4Address() ? Utils::ipv4ToString(arguments.getVictim1Ipv4Address())
                                                  : Utils::ipv6ToString(arguments.getVictim1Ipv6Address())) << endl;
        cout << "victim 1 mac: "
             << Utils::formatMacAddress(arguments.getVictim1MacAddress(), six_groups_of_two_hexa_digits_sep_colon)
             << endl;
        cout << "victim 2 ip: "
             << (arguments.isVictim2Ipv4Address() ? Utils::ipv4ToString(arguments.getVictim2Ipv4Address())
                                                  : Utils::ipv6ToString(arguments.getVictim2Ipv6Address())) << endl;
        cout << "victim 2 mac: "
             << Utils::formatMacAddress(arguments.getVictim2MacAddress(), six_groups_of_two_hexa_digits_sep_colon)
             << endl;
    }
    catch (InvalidArgumentsException &e) {
        cerr << e.what() << endl;
        SpoofArguments::printUsage();
        return EXIT_FAILURE;
    }
    catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
