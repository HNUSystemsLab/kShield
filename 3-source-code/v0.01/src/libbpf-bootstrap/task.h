#ifndef TASK_H
#define TASK_H

#define statfunc static __always_inline

//PROTOTYPES
statfunc u32 get_task_pid_vnr(struct task_struct *task);
statfunc u32 get_task_ns_pid(struct task_struct *task); // 获取task的tid
statfunc u32 get_task_ns_tgid(struct task_struct *task); // 获取task的pid
statfunc u32 get_task_ns_ppid(struct task_struct *task); // 获取task的ppid

//FUNCTIONS
statfunc u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

    pid = BPF_CORE_READ(task, thread_pid);//要求：内核版本>=5.0

    level = BPF_CORE_READ(pid, level);//pid是一个层次化的结构，为了支持进程组等机制

    return BPF_CORE_READ(pid, numbers[level].nr);
}

statfunc u32 get_task_ns_pid(struct task_struct *task)
{
    return get_task_pid_vnr(task);
}

// 对于一个线程组，领头线程（group_leader）的线程 ID（pid）等于 tgid
statfunc u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    return get_task_pid_vnr(group_leader);
}

statfunc u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = BPF_CORE_READ(task, real_parent);
    return get_task_pid_vnr(real_parent);
}

#endif