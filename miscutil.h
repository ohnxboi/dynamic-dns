#ifndef MISCUTIL_H
#define MISCUTIL_H
#include <stdio.h>
#include <stdlib.h>

void error(char *msg);
void hexDump(char *desc, void *addr, int len);

#endif /* MISCUTIL_H */
