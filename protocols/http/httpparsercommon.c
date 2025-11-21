#include "httpparsercommon.h"

int httpparser_is_ctl(int c) {
    return (c >= 0 && c <= 31) || (c == 127);
}