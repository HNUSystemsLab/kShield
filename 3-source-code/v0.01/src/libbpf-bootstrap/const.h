# ifndef CONST_H
# define CONST_H

#define MAX_PERCPU_BUFSIZE (1 << 15)  // set by the kernel as an upper bound 
#define MAX_PATH_COMPONENTS   20 
#define MAX_BIN_PATH_SIZE   256       // max binary path size
#define MAX_STRING_SIZE    4096       // same as PATH_MAX
#define MAX_STACK_DEPTH 0x20
#define ADDRS_BYTE_LEN 8

enum buf_idx_e
{
    STRING_BUF_IDX,
    FILE_BUF_IDX,
    MAX_BUFFERS
};

# endif