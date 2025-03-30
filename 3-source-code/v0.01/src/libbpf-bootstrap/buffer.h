#ifndef BUFFER_H
#define BUFFER_H

# include "maps.h"

#define statfunc static __always_inline

statfunc buf_t *get_buf(int idx);

statfunc buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

#endif