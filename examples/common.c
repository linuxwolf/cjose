
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

bool _read_stdin(uint8_t **input, size_t *amt)
{
    size_t  BLOCKSIZE = 1024;
    size_t  size = 0;
    size_t  len;
    uint8_t *buffer = malloc(BLOCKSIZE);
    uint8_t *pos = buffer;

    while (buffer)
    {
        len = fread(pos, 1, BLOCKSIZE, stdin);
        size += len;
        if (feof(stdin))
        {
            break;
        }
        if (ferror(stdin))
        {
            free(buffer);
            return false;
        }
        if (BLOCKSIZE == len)
        {
            buffer = realloc(buffer, (size + BLOCKSIZE));
            pos = (uint8_t *)((uintptr_t)buffer + size);
        }
    }
    if (NULL == buffer)
    {
        return false;
    }

    // strip newlines ...
    while ('\n' == buffer[size-1] || '\r' == buffer[size-1])
    {
        size--;
    }
    *amt = size;
    *input = buffer;

    return true;
}
