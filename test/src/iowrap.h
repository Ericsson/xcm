#ifndef IOWRAP_H
#define IOWRAP_H

#include <stdint.h>

void iowrap_drop_on_send(int domain, int type, int protocol, uint16_t port);
void iowrap_clear(void);

#endif
