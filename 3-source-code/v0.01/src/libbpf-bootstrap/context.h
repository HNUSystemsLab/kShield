# ifndef CONTEXT_H
# define CONTEXT_H

#include "types.h"
#include "task.h"

#define statfunc static __always_inline

// PROTOTYPES
statfunc int init_context(context_info_t *context);

//FUNCTIONS
statfunc int init_context(context_info_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task); 
    context->ppid = get_task_ns_ppid(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));

    // Save timestamp in microsecond resolution
    context->ts = bpf_ktime_get_ns()/1000;

    return 0;
}

# endif