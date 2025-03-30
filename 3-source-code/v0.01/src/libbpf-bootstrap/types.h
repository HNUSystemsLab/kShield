# ifndef TYPES_H
# define TYPES_H

# include "const.h"

#define TASK_COMM_LEN 16
#define FILE_NMAE_LEN 32
#define MAX_CACHED_PATH_SIZE 64

typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;


enum event_id
{
    CFI_VIOLATION,
    TASK_CRED_OVERWRITTEN,
    EVIL_OPEN,
    MODPROBE_PATH_OVERWRITTEN,
    FILE_MODIFICATION,
    MAX_EVENT_NUM,
};

enum hook_funcs_id
{
    CFI_TRACE,
    TRACE_COMMIT_CREDS,
    TRACE_RET_COMMIT_CREDS,
    RP_SYS_ENTER,
    RP_SYS_EXIT,
    TRACE_EVIL_OPEN,
    TRACE_DO_LINKAT,
    TP_TRACE_EXEC,
    RP_SYS_EXIT_CHECK_MODPROBE,
    TRACE_FD_INSTALL,
    TRACE_FLIP_CLOSE,
    TRACE_FILE_UPDATE_TIME,
    TRACE_RET_FILE_UPDATE_TIME,
    TRACE_FILE_MODIFIED,
    TRACE_RET_FILE_MODIFIED,
    MAX_HOOKS_NUM
};

enum security_file_id
{
    ETC_PASSWD,
    ETC_SHADOW,
    ETC_GROUP,
    ETC_GSHADOW,
    ETC_SUDOERS,
    MAX_SECURITY_FILE_ID,
};

enum file_modification_op
{
    FILE_MODIFICATION_SUBMIT = 0,
    FILE_MODIFICATION_DONE,
};

typedef struct env
{
	bool event[MAX_EVENT_NUM];
	int trace_all;
} env_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

typedef struct file_id {
    dev_t device; // vmlinux.h
    unsigned long inode;
    u64 ctime;
} file_id_t;

typedef struct file_pathname {
    char name[MAX_CACHED_PATH_SIZE];
} file_pathname_t;

typedef struct file_mod_key {
    dev_t device;
    unsigned long inode;
} file_mod_key_t;

typedef struct syscall_mod_key {
    u32 syscall_id;
    u32 pid;
} syscall_mod_key_t;

typedef struct file_info {
    union {
        char pathname[MAX_CACHED_PATH_SIZE];
        char *pathname_p;
    };
    file_id_t id;
} file_info_t;

typedef struct cred_info {
    u32 old_uid;
    u32 new_uid;
} cred_info_t;

typedef struct context_info {
    enum event_id eventid;
    u64 ts;                     // Timestamp
    u32 pid;                    // PID as in the userspace term
    u32 tid;                    // TID as in the userspace term
    u32 ppid;                   // Parent PID as in the userspace term
    u32 uid;
    char comm[TASK_COMM_LEN];
    s64 retval;
} context_info_t;

typedef struct program_info {
    // 整体context
    context_info_t context; //根据eventid决定如何解析
    
    // 文件修改相关信息
    enum security_file_id security_file;
    dev_t device; 
    unsigned long inode;
    u64 old_ctime;
    u64 new_ctime;
    
    // commit_cred相关信息
    u32 old_uid;
    u32 new_uid;

    //cfi破坏相关信息
    unsigned long reg_sp;
    unsigned long current_sp;
    unsigned long ip;

} program_info_t;

# endif