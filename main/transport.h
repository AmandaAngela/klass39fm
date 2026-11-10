#pragma once
#include <stddef.h>
void transport_init(void);
int transport_read(void *data, size_t size);
int transport_write(const void *data, size_t size);
