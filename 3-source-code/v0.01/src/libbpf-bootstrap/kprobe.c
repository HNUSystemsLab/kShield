// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */
#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "types.h"
#include "kprobe.skel.h"
#include "tools.h"
#include "filtering.h"

#define PERF_POLL_TIMEOUT_MS 100
#define PERF_BUFFER_PAGES 16

static volatile sig_atomic_t exiting = 0;
struct kprobe_bpf *skel;
struct env env = {{0}, 0};

const char *argp_program_version = "secure-ebpf 0.0";
const char *argp_program_bug_address = "<boyingc963@gmail.com>";
const char argp_program_doc[] =
"This poject is a kernel runtime security enforcement based on eBPF. It traces 3 kinds of security events and kill pontenial evil process.\n"
"\n"
"EVENT 0: CFI_VIOLATION. It implements control flow integrity based on eBPF.\n"
"EVENT 1: TASK_CRED_OVERWRITTEN. It checks illegal task cred modification.\n"
"EVENT 2: EVIL_OPEN. It traces the frequency of security files open.\n"
"EVENT 3: MODPROBE_PATH_OVERWRITTEN. It trace illegal modification of modprobe_path.\n"
"EVENT 4: FILE_MODIFICATION. It records security file modification. \n"
"\n"

"USAGE: ./kprobe [-e <event-num> -e <event-num>...] \n";

static const struct argp_option opts[] = {
	{ "event", 'e', "NUM", 0, "specify enabled events" },
	{ "all", 'a', NULL, 0, "trace all 4 events" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'e':
	{
		int event_num = atoi(arg);
		printf("%d\n",event_num);
		//检查传入的event_num是否合法
		if(event_num >= MAX_EVENT_NUM || event_num < 0)
		{
			fprintf(stderr, "Invalid event_num: %s\n", arg);
			argp_usage(state);
		}
		else //被使能的event
		{
			env.event[event_num] = true;
		}
		
		break;
	}
	case 'a':
		env.trace_all = 1;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void sig_init(int signo)
{
	exiting = 1;
}

/* callback function, used for processing perf data */
void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) 
{
	program_info_t info;

	/* Copy data as alignment in the perf buffer isn't guaranteed. */
	memcpy(&info, data, sizeof(info));
	
	// 时间戳
	struct tm *tm;
	char ts[32];
	time_t t;
	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// 根据eventid处理数据
	switch (info.context.eventid)
	{
	case FILE_MODIFICATION:
	{
		char fname[MAX_CACHED_PATH_SIZE]; 
		int i;
		for(i = 0; i < MAX_SECURITY_FILE_ID; i++)
		{
			if(info.security_file == ETC_PASSWD)
			{
				strncpy(&fname[0], skel->rodata->security_files[i], MAX_CACHED_PATH_SIZE);
				break;
			}
		}
		if(i == MAX_SECURITY_FILE_ID)
			return;

		if(info.context.uid == 0) //是合法的修改，只打印出事件信息；
			printf("%-16s %-16s %-16d %-20s uid=%d %-16s\n", \
		 		ts, info.context.comm, info.context.pid, "FILE_MODIFICATION", info.context.uid, &fname[0]);
		else 
		{
			printf("%-16s %-16s %-16d %-20s uid=%d %-16s ILLEGAL!!!!!!\n", \
		 		ts, info.context.comm, info.context.pid, "FILE_MODIFICATION", info.context.uid, &fname[0]);
		
			restore_backup(skel->rodata->security_files[i]);//安全敏感文件可能已被恶意篡改,根据初始化时的备份回滚
		}

		break;
	}
	case EVIL_OPEN:
		printf("%-16s %-16s %-16d %-20s KILLED!!!\n", \
			ts, &info.context.comm[0], info.context.pid, "EVIL_OPEN");
		break;
	case TASK_CRED_OVERWRITTEN: 
		printf("%-16s %-16s %-16d %-20s KILLED!!!\n", \
			ts, &info.context.comm[0],  info.context.pid, "TASK_CRED_OVERWRITTEN");
		break;
	case MODPROBE_PATH_OVERWRITTEN: 
	{
		printf("%-16s %-16s %-16d %-20s KILLED!!!\n", \
			ts, &info.context.comm[0],  info.context.pid, "MODPROBE_PATH_OVERWRITTEN");
		
		//回滚modprobe_path
		if(!modprobe_roll_back(skel))
		{
			skel->bss->modprobe_overwritten = 0;
		}
		printf("modprobe_overwritten = %d\n", skel->bss->modprobe_overwritten);
		
		//杀死恶意进程
		if (kill(info.context.pid, 9) == -1) 
		{
			perror("send kill failed");
			return;
		}
		printf("evil process %s pid = %d killed!!!\n", &info.context.comm[0], info.context.pid);

		break;
	}
	case CFI_VIOLATION:
	{
		printf("%-16s %-16s %-16d %-20s KILLED!!! \n", \
			ts, &info.context.comm[0], info.context.pid, "CFI_VIOLATION");
		//打印出堆栈信息
		std::cout << "Hook function: " << bpf_ksyms_resolve(info.ip) << " (" << std::hex << info.ip << std::dec << ")" << std::endl;
		std::cout << "Stack pointer: " << std::hex << info.reg_sp <<" - "<< info.current_sp << std::dec << std::endl;
		break;
	}
	default:
		break;
	}

	return;
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) 
{
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	time_t start_time;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = kprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	//初始化hooks
	bpf_hooks_init(&env, skel);

	//根据准备追踪的事件，做一些初始化
	traced_event_init(&env, skel);

	/* Attach kprobe */
	err = kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* receive and process event */
	pb = perf_buffer__new(bpf_map__fd(skel->maps.program_submit_map), PERF_BUFFER_PAGES, handle_event, handle_lost_events, NULL, NULL);
	
	if (libbpf_get_error(pb)) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
	}

	if (signal(SIGINT, sig_init) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	/* Process events */
	printf("%-16s %-16s %-16s %-20s \n", "TIME", "COMM", "PID", "EVENT");

	start_time = time(NULL);
	/* main: poll */
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        /* reset err to return 0 if exiting */
        err = 0;
		// 处理时间,每过10s清空一次open_cnt.这样次数就变成了(平均)速率
		time_t current_time = time(NULL);
    	if (current_time - start_time >= 100)
		{
			//reset open_cnt
        	skel->bss->open_cnt = 0;
			// Reset the start time
        	start_time = current_time; 
    	}
    }
	
cleanup:
	perf_buffer__free(pb);
	kprobe_bpf__destroy(skel);

	return -err;
}