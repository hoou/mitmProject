#include "Arguments.h"

InvalidArgumentsException::InvalidArgumentsException() : runtime_error("Invalid arguments") {}

InvalidArgumentsException::InvalidArgumentsException(const string &__arg) : runtime_error(
        "Invalid arguments: " + __arg) {}
