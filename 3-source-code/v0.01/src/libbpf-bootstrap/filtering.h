#ifndef FILTERING_H
#define FILTERING_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "types.h"
#include "kprobe.skel.h"

//PROTOTYPE
void set_hooks_by_event_num(int num, struct kprobe_bpf *skel);
void bpf_hooks_init(struct env* env, struct kprobe_bpf *skel);


//FUCNS
void set_hooks_by_event_num(int num, struct kprobe_bpf *skel)
{
	switch (num)
	{
	case CFI_VIOLATION:
		skel->bss->should_trace_hooks[CFI_TRACE] = 1;
		break;
	case TASK_CRED_OVERWRITTEN:
		skel->bss->should_trace_hooks[TRACE_COMMIT_CREDS] = 1;
		skel->bss->should_trace_hooks[TRACE_RET_COMMIT_CREDS] = 1;
		skel->bss->should_trace_hooks[RP_SYS_ENTER] = 1;
		skel->bss->should_trace_hooks[RP_SYS_EXIT] = 1;
		break;
	case EVIL_OPEN:
		skel->bss->should_trace_hooks[TRACE_EVIL_OPEN] = 1;
		skel->bss->should_trace_hooks[TRACE_DO_LINKAT] = 1;
		break;
	case MODPROBE_PATH_OVERWRITTEN:
		skel->bss->should_trace_hooks[TP_TRACE_EXEC] = 1;
		skel->bss->should_trace_hooks[RP_SYS_EXIT_CHECK_MODPROBE] = 1;
	case FILE_MODIFICATION:
		skel->bss->should_trace_hooks[TRACE_FD_INSTALL] = 1;
		skel->bss->should_trace_hooks[TRACE_FLIP_CLOSE] = 1;
		skel->bss->should_trace_hooks[TRACE_FILE_UPDATE_TIME] = 1;
		skel->bss->should_trace_hooks[TRACE_RET_FILE_UPDATE_TIME] = 1;
		skel->bss->should_trace_hooks[TRACE_FILE_MODIFIED] = 1;
		skel->bss->should_trace_hooks[TRACE_RET_FILE_MODIFIED] = 1;
		break;
	default:
		break;
	}
	printf("init hooks for event %d\n",num);
}

void bpf_hooks_init(struct env* env, struct kprobe_bpf *skel)
{
	if(env->trace_all == 1)
	{
		for(int i = 0; i < MAX_EVENT_NUM; i++)
		{
			set_hooks_by_event_num(i, skel);
		}
	}
	else
	{
		for(int i = 0; i < MAX_EVENT_NUM; i++)
		{
			if(env->event[i] == 1)
			{
				set_hooks_by_event_num(i, skel);
			}
		}
	}
}

#endif