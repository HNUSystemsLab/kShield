# ifndef MAPS_H
# define MAPS_H

# include "types.h"
# include "const.h"

// persist args between function entry and return
struct args_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, args_t);
} args_map SEC(".maps");

typedef struct args_map args_map_t;


// percpu global buffer variables
struct bufs {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUFFERS);
    __type(key, u32);
    __type(value, buf_t);
} bufs SEC(".maps"); 

typedef struct bufs bufs_t;

//合法调用地址的bitmap
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 0x4000000);
    __type(key, unsigned);
    __type(value, uint8_t);
} callsite_bitmap SEC(".maps");

typedef struct callsite_bitmap callsite_bitmap_t;

//地址空间的上限和下限
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, unsigned);
    __type(value, unsigned);
} callsite_bitmap_maxmin SEC(".maps");

typedef struct callsite_bitmap_maxmin callsite_bitmap_maxmin_t;

//初始栈地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, unsigned long);
} init_stack SEC(".maps");

typedef struct init_stack init_stack_t;

//内核函数调用栈
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 0x1000);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} kstack_table SEC(".maps");

typedef struct kstack_table kstack_table_t;

//modprobe_path的地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, unsigned long);
} modprobe_path SEC(".maps");

typedef struct modprobe_path modprobe_path_t;

// hold sys_enter/exit data to decide if should submit event
struct syscall_trace_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, syscall_mod_key_t); 
    __type(value, u32); // uid
} syscall_trace_map SEC(".maps");

typedef struct syscall_trace_map syscall_trace_map_t;


// hold file data to decide if should submit file modification event
struct file_modification_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, file_mod_key_t);
    __type(value, s32);
} file_modification_map SEC(".maps");

typedef struct file_modification_map file_modification_map_t;


// hold cred data to decide if should submit cred modification event
struct cred_modification_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // pid
    __type(value, cred_info_t); // (old_uid, new_uid)
} cred_modification_map SEC(".maps");

typedef struct cred_modification_map cred_modification_map_t;


// hold total program data and submit to userspace
struct program_submit_map{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} program_submit_map SEC(".maps");

# endif