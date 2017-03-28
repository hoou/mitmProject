#include <cstdlib>
#include <scanner/ScannerArguments.h>
#include <iostream>
#include "SpoofArguments.h"

int main(int argc, char **argv) {
    try {
        SpoofArguments arguments(argc, argv);
    } catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
