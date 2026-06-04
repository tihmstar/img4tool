#pragma once
#if defined(__APPLE__) || defined(__linux__)
#include <arpa/inet.h>
#else
// fallback
static inline unsigned long htonl(unsigned long x){ return x; }
#endif
