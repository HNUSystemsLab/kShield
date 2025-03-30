// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "context.h"
#include "filesystem.h"
#include "args.h"
#include "my_string.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EVIL_OPEN_CNT 100
#define ADDRS_BYTE_LEN 8
#define WCFI_CALLSITE_FLAG 0

const volatile char security_files[MAX_SECURITY_FILE_ID][MAX_CACHED_PATH_SIZE] = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers"
    };

const volatile char right_modprobe[15] = {"/sbin/modprobe"};
volatile char previous_modprobe[15] = {"/sbin/modprobe"}; //记录上一次modprobe_path的值（这是为了防止重复提交）
volatile int modprobe_overwritten = 0;

volatile int should_trace_hooks[MAX_HOOKS_NUM] = {0}; //0表示不需要启用该hook
volatile int open_cnt = 0; //记录各安全敏感文件被打开的次数

//PROTOTYPE
statfunc int common_file_modification_ent(struct pt_regs *ctx);
statfunc int common_file_modification_ret(struct pt_regs *ctx);

/*
* 名称: CFI_VIOLATION
* 功能: 基于eBPF的控制流完整性保证
* 类型: kprobe
* Hooks: commit_creds
*/
SEC("kprobe/commit_creds")
int BPF_KPROBE(cfi_trace)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[CFI_TRACE])
        return 0;

	int ret = 0;
    program_info_t info = {};
    
    if(init_context(&info.context))
        return 0;
    info.context.eventid = CFI_VIOLATION;

    struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
    unsigned long addrs[MAX_STACK_DEPTH];
    unsigned long stack_mask = ~((unsigned long)(1 << 16) - 1);

    void* curr_stack = BPF_CORE_READ(cu, stack);

    pid_t curr_pid = BPF_CORE_READ(cu, pid);

    bpf_get_stack(ctx, addrs, MAX_STACK_DEPTH * ADDRS_BYTE_LEN, 0);
	
    //检查当前函数调用栈是否位于预期的栈中，并在不符合预期的情况下，提交一个事件到用户态
     if (((unsigned long)ctx->sp & stack_mask) != ((unsigned long)curr_stack & stack_mask)) 
     {
        int init_stack_idx = 0;
        unsigned long *init_stack_ptr = bpf_map_lookup_elem(&init_stack, &init_stack_idx);
        if(!init_stack_ptr)
        {
            bpf_printk("init_stack failed bpf_map_lookup_elem");
            return 0;
        }
        
        if (init_stack_ptr && ((unsigned long)curr_stack != *init_stack_ptr) && curr_pid != 0)
        {
            // PID:0 (swapper/0)
            struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
            info.reg_sp = ctx->sp;
            void* curr_sp = BPF_CORE_READ(cu, stack);
            info.current_sp = (unsigned long)curr_sp;
            unsigned long curr_ip = BPF_CORE_READ(cu, thread.sp);
            info.ip = curr_ip;
            
            bpf_printk("not in proper stack\n");
            bpf_send_signal_thread(9);

            goto submit;
            
         } // failed 
     }
    
    //该循环用于遍历函数调用栈，并检查每个地址是否匹配预定义的条件
    for(int i = 1; i < MAX_STACK_DEPTH; i++) 
    {
        unsigned idx = addrs[i] & 0xffffffff; // 取低32位（高位全是f）
        if (idx == 0)
            break;

        uint8_t *val;
        val = bpf_map_lookup_elem(&callsite_bitmap, &idx);
        
        // right callsite
        if (val) 
        {
            if (*val == WCFI_CALLSITE_FLAG)
                continue;
        }
        if(!val) 
        {
            unsigned max_idx = 0xffff, min_idx = 0x0;
            unsigned *max = bpf_map_lookup_elem(&callsite_bitmap_maxmin, &max_idx);
            unsigned *min = bpf_map_lookup_elem(&callsite_bitmap_maxmin, &min_idx);
            //地址不合法(不在内核地址空间内)
            if (min && max && (idx > *max || idx < *min))
                continue;
        }
        if (idx != 0 && !val) 
        {
            //地址合法且找不到（val=NULL）说明这是一个不合法的调用地址。将事件记录下来并提交到用户态。
            info.reg_sp = ctx->sp;
            void* stack = BPF_CORE_READ(cu, stack);
            info.current_sp = (unsigned long)stack;
            info.ip = addrs[i];
            
            bpf_printk("cfi violated!\n");
            bpf_send_signal_thread(9);
            
            goto submit;
            break;
        }
    }

     return 0;

submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
    if(ret < 0)
    {
        bpf_printk("bpf_perf_event_output error\n");
        return 0;
    } 

    return 0;
}

/*
* 名称: TASK_CRED_OVERWRITTEN
* 功能: 检测进程cred是否被恶意覆写，若是，杀死恶意进程。
* Hooks: 
*    commit_creds(kprobe & kretprobe)
*    sys_enter(raw_tracepoint)
*    sys_exit(raw_tracepoint)
*/

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_COMMIT_CREDS])
        return 0;

    struct task_struct* task;
    kuid_t uid;
    task = (struct task_struct *)bpf_get_current_task();
    uid = BPF_CORE_READ(task, cred, uid);

    //记录执行commit_creds之前的uid
    args_t args = {};
    args.args[0] = uid.val; 
    save_args(&args, TASK_CRED_OVERWRITTEN);

    return 0;
}

SEC("kretprobe/commit_creds")
int BPF_KPROBE(trace_ret_commit_creds, struct cred *new)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_RET_COMMIT_CREDS])
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, TASK_CRED_OVERWRITTEN) != 0)
        return 0;
    del_args(TASK_CRED_OVERWRITTEN);

    u32 old_uid = saved_args.args[0]; 
    u32 new_uid = bpf_get_current_uid_gid();
    u32 pid = bpf_get_current_pid_tgid();

    //commit_creds前后进程号=pid的进程的<new_uid, old_uid>记录到map中，以备sys_exit时check
    cred_info_t cred_info = {old_uid, new_uid};
    bpf_map_update_elem(&cred_modification_map, &pid, &cred_info, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{   
    //检查这个hook是否启用
    if(!should_trace_hooks[RP_SYS_ENTER])
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    u32 syscall_id = ctx->args[1];
    u32 uid = bpf_get_current_uid_gid();

    syscall_mod_key_t syscall_mod_key = {syscall_id, pid};
    bpf_map_update_elem(&syscall_trace_map, &syscall_mod_key, &uid, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint__sys_exit(struct bpf_raw_tracepoint_args *ctx) 
{
    //检查这个hook是否启用
    if(!should_trace_hooks[RP_SYS_EXIT])
        return 0;

    int ret = 0;
    program_info_t info = {};

    if (init_context(&info.context))
        return 0;

    struct pt_regs *regs = (struct pt_regs*)ctx->args[0];
    
    u32 syscall_id = BPF_CORE_READ(regs, orig_ax);
    u32 pid = bpf_get_current_pid_tgid();
    syscall_mod_key_t syscall_mod_key = {syscall_id, pid};

    u32 uid = bpf_get_current_uid_gid();
    u32 *old_uid = bpf_map_lookup_elem(&syscall_trace_map, &syscall_mod_key);
    if(old_uid == NULL)
    {
        return 0;
    }

    // 查询commit_creds情况
    cred_info_t* changed = bpf_map_lookup_elem(&cred_modification_map, &pid);
    if(changed == NULL && *old_uid != uid) // 没有发生commit_creds事件,但uid变化了
    {
        bpf_printk("no commit_creds: %d %d",*old_uid,uid);
        bpf_printk("illegal cred overwrite found!!!");
        bpf_send_signal_thread(9);

        info.context.eventid = TASK_CRED_OVERWRITTEN;
        info.old_uid = *old_uid;
        info.new_uid = uid;
        
        goto submit;
        
    }
    else if(changed == NULL && *old_uid == uid)
    {
        return 0; // 没有发生commit_creds事件且uid没有变化
    }
    else //发生了commit_creds事件
    {
        if(*old_uid != uid)
        {
            bpf_printk("TASK_CRED_MODIFICATION: %d %d",*old_uid, uid);
        }
        bpf_map_delete_elem(&cred_modification_map, &pid);
    }

    return 0;

// 提交事件到用户态    
submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
    if(ret < 0)
    {
        bpf_printk("bpf_perf_event_output error %d\n",ret);
        return 0;
    }

    return 0;
}


/*
* 名称: EVIL_OPEN
* 功能: 通过检查安全敏感文件被打开的频率，检测是否发生DirtyCred攻击，若是，杀死恶意进程。do_linkat阻止在安全敏感文件上建立硬链接
* Hooks: 
*    fd_install(kprobe)
*    do_linkat(kprobe)
*/
SEC("kprobe/fd_install")
int BPF_KPROBE(trace_evil_open,unsigned int fd, struct file *file)
{
    if(!should_trace_hooks[TRACE_EVIL_OPEN])
        return 0;

	// 检测打开文件的类型是否是普通文件，若不是，不提交该事件
	unsigned short file_mode = get_inode_mode_from_file(file);
	if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    int ret = 0;
    program_info_t info = {};

    if (init_context(&info.context))
        return 0;

	// 获取文件基本信息
	file_info_t file_info = get_file_info(file);

    file_pathname_t path = {};
    bpf_probe_read_kernel_str(&path.name[0],sizeof(path.name),file_info.pathname_p);
    
    int i;
    for(i = 0; i < MAX_SECURITY_FILE_ID; i++)
    {
        if(!my_bpf_strncmp(&path.name[0], sizeof(path.name), &security_files[i]))
        {
            bpf_printk("open_cnt=%d", open_cnt);
            open_cnt++;
            break;
        }
    }

    if(open_cnt > EVIL_OPEN_CNT)
    {
        open_cnt = 0;

        bpf_send_signal_thread(9);
        info.context.eventid = EVIL_OPEN;
        bpf_printk("pid = %d comm = %s EVIL OPEN KILLED!!!",info.context.pid, &info.context.comm[0]);
        
        goto submit;
    } 
	
	return 0;

submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
    if(ret < 0)
    {
        bpf_printk("bpf_perf_event_output error\n");
        return 0;
    } 
    return 0; 
}



SEC("kprobe/do_linkat")
int BPF_KPROBE(trace_do_linkat, int olddfd, struct filename *old, int newdfd, struct filename *new, int flags)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_DO_LINKAT])
        return 0;

    const char* old_name_p = NULL;
    char filename[MAX_CACHED_PATH_SIZE];

    old_name_p = BPF_CORE_READ(old, name);
    bpf_probe_read_kernel_str(&filename[0],sizeof(filename),old_name_p);
    
    //检查这个硬链接是不是与安全敏感文件相关
    for(int i = 0; i < MAX_SECURITY_FILE_ID; i++)
    {
        if(my_bpf_strncmp(&filename[0], sizeof(&filename), &security_files[i]))
        {
            bpf_printk("build hard link on security file %s: not allowd", &security_files[i]); //不允许的操作
            bpf_send_signal_thread(9);
            break;
        }
    }

    return 0;
}


/*
* 名称: MODPROBE_PATH_OVERWRITTEN
* 功能: 监测modprobe_path是否被恶意覆写，如果是，杀死恶意进程
* Hooks: 
*    sched_process_exec(tracepoint)
*    sys_exit(raw_tracepoint)
*/
SEC("tp/sched/sched_process_exec")
int tp_trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TP_TRACE_EXEC])
        return 0;

    //如果检测到modprobe_path已经被覆写，禁止新的进程开始执行
    //因为该利用方式提权的方式是：覆写modprobe_path后，以suid权限执行恶意脚本，这种方式需要创建新进程。
    if(modprobe_overwritten)
    {
        //SIGSTP 不让新进程开始执行
        bpf_send_signal_thread(20);
    }

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int rp_sys_exit_check_modprobe(struct bpf_raw_tracepoint_args *ctx) 
{
    //检查这个hook是否启用
    if(!should_trace_hooks[RP_SYS_EXIT_CHECK_MODPROBE])
        return 0;

    int ret = 0;
    unsigned key = 0;
    program_info_t info = {};
    if (init_context(&info.context))
        return 0;

    unsigned long *value = NULL;
    char mdprobe_content[15];

    //从内核符号kallsyms中可以取得modprobe_path的地址。从该处读取当前modprobe_path的内容
    value = bpf_map_lookup_elem(&modprobe_path, &key);
    if(!value)
    {
        bpf_printk("read modprobe_path from map failed");
        return 0;
    }
    bpf_probe_read_kernel_str(&mdprobe_content[0],sizeof(mdprobe_content), (const void *)(*value));
    
    //如果当前的内容不等于/sbin/modprobe，说明其被覆写。
    if(my_bpf_strncmp(&mdprobe_content[0],sizeof(mdprobe_content),&right_modprobe[0]) != 0) 
    {
        //changed!!!
        bpf_printk("pid=%d comm=%s modprobe_path changed to %s",info.context.pid, info.context.comm, &mdprobe_content[0]);

        /*
        * 在检测到被覆写和事件被提交到用户态得到处理的时间窗口内，会触发好多次sys_exit。为了防止事件重复提交，记录一个previous_modprobe.
        * 如果当前mdprobe_content不等于/sbin/modprobe，但是等于previous_modprobe，就不再重复提交事件。
        */
        if(my_bpf_strncmp(&mdprobe_content[0],sizeof(mdprobe_content),&previous_modprobe[0]) != 0)
        {
            bpf_probe_read_kernel_str(&previous_modprobe[0],sizeof(previous_modprobe), &mdprobe_content[0]); //更新previous_modprobe

            //准备提交
            info.context.eventid = MODPROBE_PATH_OVERWRITTEN;
            modprobe_overwritten = 1;
            goto submit;
        }
    }

    return 0;

submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
    if(ret < 0)
    {
        bpf_printk("bpf_perf_event_output error %d\n", ret);
        return 0;
    }

    return 0;
}

/*
* 名称: FILE_MODIFICATION
* 功能: 记录对安全敏感文件的修改,如果修改是非法的，回滚（TODO）
* Hooks: 
*    fd_install(kprobe)
*    filp_close(kprobe)
*    file_update_time(kprobe & kretprobe)
*    file_modified(kprobe & kretprobe)
*/
// Catch the open of a file and set the event of file_modification to be submitted for it
SEC("kprobe/fd_install")
int BPF_KPROBE(trace_fd_install,unsigned int fd, struct file *file)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_FD_INSTALL])
        return 0;

	// 检测打开文件的类型是否是普通文件，若不是，不提交该事件
	unsigned short file_mode = get_inode_mode_from_file(file);
	if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

	// 获取文件基本信息
	file_info_t file_info = get_file_info(file);

	// 将获取到的文件信息存储到file_modification_map中
    file_mod_key_t file_mod_key = {};
    file_mod_key.inode = file_info.id.inode;
    file_mod_key.device = file_info.id.device;
	int op = FILE_MODIFICATION_SUBMIT;
	bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);

    return 0;
}

// Catch the close of a file and remove it from cache of files t submit the event for
SEC("kprobe/filp_close")
int BPF_KPROBE(trace_filp_close,struct file *filp, fl_owner_t id)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_FLIP_CLOSE])
        return 0;

    file_info_t file_info = get_file_info(filp);

    file_mod_key_t file_mod_key = {};
    file_mod_key.inode = file_info.id.inode;
    file_mod_key.device = file_info.id.device;

    bpf_map_delete_elem(&file_modification_map, &file_mod_key);

    return 0;
}

//Catch the file ctime change and submit the event if marked to be submitted
SEC("kprobe/file_update_time")
int BPF_KPROBE(trace_file_update_time)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_FILE_UPDATE_TIME])
        return 0;

    return common_file_modification_ent(ctx);
}

SEC("kretprobe/file_update_time")
int BPF_KPROBE(trace_ret_file_update_time)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_RET_FILE_UPDATE_TIME])
        return 0;

    return common_file_modification_ret(ctx);
}

//与file_update_time处的hook功能相同，有它是为了同时支持新旧内核版本。
//Catch the file ctime change and submit the event if marked to be submitted
SEC("kprobe/file_modified")
int BPF_KPROBE(trace_file_modified)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_FILE_MODIFIED])
        return 0;
    /*
     * we want this probe to run only on kernel versions >= 6.
     * this is because on older kernels the file_modified() function calls the file_update_time()
     * function. in those cases, we don't need this probe active.
     */
    if (bpf_core_field_exists(((struct file *) 0)->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ent(ctx);
    }

    return 0;
}

SEC("kretprobe/file_modified")
int BPF_KPROBE(trace_ret_file_modified)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_RET_FILE_MODIFIED])
        return 0;
    /*
     * we want this probe to run only on kernel versions >= 6.
     * this is because on older kernels the file_modified() function calls the file_update_time()
     * function. in those cases, we don't need this probe active.
     */
    if (bpf_core_field_exists(((struct file *) 0)->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ret(ctx);
    }

    return 0;
}

statfunc int common_file_modification_ent(struct pt_regs *ctx)
{
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);

    // check if regular file. otherwise don't output the event.
    unsigned short file_mode = get_inode_mode_from_file(file);
    if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    u64 ctime = get_ctime_nanosec_from_file(file);

    args_t args = {};
    args.args[0] = (unsigned long) file;
    args.args[1] = ctime;
    save_args(&args, FILE_MODIFICATION);

    return 0;
}

statfunc int common_file_modification_ret(struct pt_regs *ctx)
{
    int ret = 0;
    program_info_t info = {};

    if (init_context(&info.context))
        return 0;

    info.context.eventid = FILE_MODIFICATION;
    info.context.retval = PT_REGS_RC(ctx);

    args_t saved_args = {};
    if (load_args(&saved_args, FILE_MODIFICATION) != 0)
        return 0;
    del_args(FILE_MODIFICATION);

    struct file *file = (struct file *) saved_args.args[0];
    u64 old_ctime = saved_args.args[1];

    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {};
    file_mod_key.inode = file_info.id.inode;
    file_mod_key.device = file_info.id.device;

    int *op = bpf_map_lookup_elem(&file_modification_map, &file_mod_key);
    if (op == NULL || *op == FILE_MODIFICATION_SUBMIT) {
        // we should submit the event once and mark as done.
        int op = FILE_MODIFICATION_DONE;
        bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);
    } else {
        // no need to submit. return.
        return 0;
    }
   
    //feed info
    info.device = file_info.id.device;
    info.inode = file_info.id.inode;
    info.old_ctime = old_ctime;
    info.new_ctime = file_info.id.ctime;
    //filename
    file_pathname_t path = {};
    bpf_probe_read_kernel_str(&path.name[0],sizeof(path.name),file_info.pathname_p);
    //bpf_printk("in common_file_modification_ret: %s inode=%d",file_info.pathname_p,file_info.id.inode);
    int i;
    for(i = 0; i < MAX_SECURITY_FILE_ID; i++)
    {
        if(!my_bpf_strncmp(&path.name[0], sizeof(path.name), &security_files[i]))
        {
            info.security_file = i; 
            break;
        }
    }

    //提交
    if(i < MAX_SECURITY_FILE_ID)
    {
        ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
        if(ret < 0)
        {
            bpf_printk("bpf_perf_event_output error\n");
            return 0;
        } 
        return 0;
    }

    return 0;
}



