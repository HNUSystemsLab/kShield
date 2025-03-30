#ifndef TOOLS_H
#define TOOLS_H

#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include"types.h"

#define WCFI_CALLSITE_FLAG 0
#define MAX_BUF_SIZE 1024
#define FILE_BUFFER_SIZE 4096 //file
#define NUM_FILES 5

//这个文件中集合了一些用户态工具函数

//PROTOTYPE
std::vector<unsigned long> read_objdump(const char *objfile, unsigned long start, unsigned long *end, bool kcore);
unsigned long read_kallsyms(std::string obj_sym);
std::string get_kernel_version();
void bpf_callsite_bitmap_update(struct kprobe_bpf *skel, unsigned long addr, uint8_t new_flag);
std::string bpf_ksyms_resolve(unsigned long ip);
int bpf_cfi_maps_init(struct kprobe_bpf *skel, unsigned min, unsigned max, unsigned long init_stack);
int modprobe_path_map_init(struct kprobe_bpf *skel, unsigned long modprobe_path_addr);
int modprobe_roll_back(struct kprobe_bpf *skel);
int security_file_backup(struct kprobe_bpf *skel);
void restore_backup(const char* security_file_path);
void traced_event_init(struct env* env, struct kprobe_bpf *skel);

//FUNSC
std::vector<unsigned long> read_objdump(const char *objfile, unsigned long start, unsigned long *end, bool kcore)
{
    std::vector<unsigned long> ret_addrs;
    char cmd[0x100] = "0", *raw_line = NULL;
    bool push_next_addr = false;
    size_t len = 0;
    FILE *objdump;

    //使用objdump打开目标文件(vmlinux-xxx)
    sprintf(cmd, "objdump --no-show-raw-insn -d %s", objfile);
    objdump = popen(cmd, "r"); 
    if (!objdump) {
        perror(cmd);
        exit(1);
    }

    while(getline(&raw_line, &len, objdump) != -1) {
        unsigned long addr;
        char inst1[0x10], inst2[0x10];

        // 如果push_next_addr被设为真，而且正确读取到了下一行，进行处理。
        if (push_next_addr && sscanf(raw_line, "%lx:", &addr)) 
        {
            if (*end < addr - 0xffffffff81000000 + start)
                *end = addr - 0xffffffff81000000 + start;

            if ((sscanf(raw_line, "%lx:\t%s\n", &addr, inst1)) &&
                (std::string(inst1).find("nop", 0) != std::string::npos)
             ) //如果读到的是nop指令，存下来，并继续把push_next_addr设为true（要读到不是nop为止）
             {
                ret_addrs.push_back(addr - 0xffffffff81000000 + start);
                push_next_addr = true;
             } 
             else 
             { //如果读到的是其他指令，直接存下来，并把push_next_addr设为false，不继续读了。
                ret_addrs.push_back(addr - 0xffffffff81000000 + start);
                push_next_addr = false;
             }
        }

        // objdump出来的call指令格式：ffffffff810035b4:       call   0xffffffff81ac5a60
        if (sscanf(raw_line, "%lx:\t%s\n", &addr, inst1)) 
        {
            if (!strncmp(inst1, "call", 5)) // 如果当前读到的是call指令，直接处理
            {
                unsigned long real_addr = addr - 0xffffffff81000000 + start;

                if (real_addr > start)
                    push_next_addr = true; // call指令的后一条是合法的返回地址
                else
                    std::cerr << "out of address space: 0x"
                              << std::hex << real_addr << std::dec << std::endl;
            } 
            else if (sscanf(raw_line, "%lx:\t%s %s\n", &addr, inst1, inst2)) //另一种可能的合理返回地址
            {
                if ((std::string(inst1).find("cs", 0) != std::string::npos) &&
                    (std::string(inst2).find("call", 0) != std::string::npos)
                )
                {
                    unsigned long real_addr = addr - 0xffffffff81000000 + start;
                    if (real_addr > start)
                        push_next_addr = true;
                    else
                        std::cerr << "out of address space: 0x"
                                  << std::hex << real_addr << std::dec << std::endl;
                }
            }
        }
    }

    return ret_addrs;
}

unsigned long read_kallsyms(std::string obj_sym)
{
    FILE *kallsyms_file;
    char *raw_line = NULL;
    size_t len = 0;

    //打开内核符号文件kallsyms
    kallsyms_file = fopen("/proc/kallsyms", "r");
    if (!kallsyms_file) {
        perror("open /proc/kallsyms failed");
        exit(1);
    }

    //遍历文件，找到名称为obj_sym的的符号的地址
    while(getline(&raw_line, &len, kallsyms_file) != -1) {
        unsigned long addr;
        char sym_type, sym[0x40] = "\0", mod[0x40] = "\0";

        //文件的内容格式: ffffffff814da820 T fd_install (地址，符号类型，名称)
        if (sscanf(raw_line, "%lx %c %s %s\n", &addr, &sym_type, sym, mod) < 3) {
            printf("failed read line: %s\n", raw_line);
            exit(1);
        }

        if (std::string(sym) == obj_sym)
            return addr;
    } 

    return 0;
}

std::string get_kernel_version() 
{
    std::string kernel_version;

    // 打开管道，执行 uname -r 命令
    FILE* uname_pipe = popen("uname -r", "r");
    if (!uname_pipe) {
        std::cerr << "Error executing uname command" << std::endl;
        exit(1);
    }

    // 读取内核版本信息
    char kernel_version_buf[256];
    if (!fgets(kernel_version_buf, sizeof(kernel_version_buf), uname_pipe)) {
        std::cerr << "Error reading kernel version" << std::endl;
        exit(1);
    }

    // 关闭管道
    pclose(uname_pipe);

    // 去除换行符并存储内核版本信息
    kernel_version = kernel_version_buf;
    kernel_version.erase(kernel_version.find_last_not_of(" \n\r\t") + 1);

    return kernel_version;
}


//初始化有效callsite的bpf map
void bpf_callsite_bitmap_update(struct kprobe_bpf *skel, unsigned long addr, uint8_t new_flag) 
{
    unsigned idx = (unsigned)(addr & 0xffffffff);

    int ret = bpf_map__update_elem(skel->maps.callsite_bitmap, &idx, sizeof(idx), &new_flag, sizeof(new_flag), BPF_ANY);
    if(ret)
	{
		std::cerr << "callsite_bitmap update failed" << strerror(errno) << std::endl;
    	exit(1);
	}
}

//根据地址解析出符号名称，例如 ffffffff814da820 ==> fd_install
std::string bpf_ksyms_resolve(unsigned long ip) 
{
    std::string kernel_version = get_kernel_version();
    std::string path = "/boot/vmlinux-" + kernel_version;

    // 构建 addr2line 命令
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "addr2line -e %s -f -s %lx", path.c_str(), ip);

    // 执行命令并获取输出
    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        return "UNKNOWN";
    }

    char buffer[256];
    std::string result;
    while (!feof(pipe)) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
    }

    pclose(pipe);

    // 仅保留第一行，并移除换行符
    size_t pos = result.find('\n');
    if (pos != std::string::npos) {
        result.erase(pos);
    }

    return result;
}

//初始化与CFI事件相关的多个bpf map
int bpf_cfi_maps_init(struct kprobe_bpf *skel, unsigned min, unsigned max, unsigned long init_stack) 
{
    unsigned key, value;
    //为callsite_bitmap_maxmin赋值
    key = 0xffff;
    value = max & 0xffffffff;
    int ret = bpf_map__update_elem(skel->maps.callsite_bitmap_maxmin, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    if(ret)
	{
		std::cerr << "callsite_bitmap_maxmin update failed: max" << strerror(errno) << std::endl;
    	exit(1);
	}

    key = 0x0;
    value = min & 0xffffffff;
    ret = bpf_map__update_elem(skel->maps.callsite_bitmap_maxmin, &key, sizeof(key), &value, sizeof(value), BPF_ANY);
    if(ret)
	{
		std::cerr << "callsite_bitmap_maxmin update failed: min" << strerror(errno) << std::endl;
    	exit(1);
	}

   //为init_stack
    key = 0x0;
    ret = bpf_map__update_elem(skel->maps.init_stack, &key, sizeof(key), &init_stack, sizeof(init_stack), BPF_ANY);
    if(ret)
	{
		std::cerr << "init_stack update failed" << strerror(errno) << std::endl;
    	exit(1);
	}

    return 1;
}

//初始化与modprobe_path覆写相关的bpf map
int modprobe_path_map_init(struct kprobe_bpf *skel, unsigned long modprobe_path_addr)
{
	
	//use it to init map
    unsigned key = 0x0;
    int ret = bpf_map__update_elem(skel->maps.modprobe_path, &key, sizeof(key), &modprobe_path_addr, sizeof(modprobe_path_addr), BPF_ANY);
    if(ret)
	{
		std::cerr << "modprobe_path_addr update failed" << strerror(errno) << std::endl;
    	exit(1);
	}

    return 1;
}

//回滚modprobe_path，成功时返回0
int modprobe_roll_back(struct kprobe_bpf *skel) 
{
    //如果没发生变化：直接返回
    if (strncmp(&skel->data->previous_modprobe[0], &skel->rodata->right_modprobe[0], 15) == 0) 
    {
        return 0;
    }

    //需要回滚
    FILE *fp;
    char buffer[MAX_BUF_SIZE];
    char original_content[MAX_BUF_SIZE];
    const char new_content[] = "/sbin/modprobe";
    int len = strlen(new_content);

    // 打开文件以读取模式打开
    fp = fopen("/proc/sys/kernel/modprobe", "r+");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    // 读取原内容并打印到屏幕上
    fgets(original_content, MAX_BUF_SIZE, fp);
    printf("Original content: %s\n", original_content);

    // 将文件指针移动到文件开头
    fseek(fp, 0, SEEK_SET);

    // 向文件中写入新内容
    if (fprintf(fp, "%s", new_content) < 0) {
        perror("Error writing to file");
        fclose(fp);
        return 1;
    }

    // 关闭文件
    fclose(fp);

    printf("Write to /proc/sys/kernel/modprobe successfully.\n");

    // 再次打开文件检查是否成功写入新内容
    fp = fopen("/proc/sys/kernel/modprobe", "r");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    // 读取文件内容并检查是否成功写入新内容
    fgets(buffer, MAX_BUF_SIZE, fp);
    fclose(fp);

    // 检查写入的内容是否正确
    if (strncmp(buffer, new_content, len) == 0) {
        printf("Success rolling back.\n");
        
        //更新previous_modprobe
        strncpy(&skel->data->previous_modprobe[0], new_content, len);
        skel->data->previous_modprobe[len] = '\0'; // 确保字符串结尾

        return 0;
    } else {
        printf("Failed!!!\n");
        return 1;
    }
}

//安全敏感文件备份，成功时返回0
int security_file_backup(struct kprobe_bpf *skel) 
{
    FILE *src_file, *dest_file;
    char buffer[FILE_BUFFER_SIZE];
    ssize_t bytes_read;
    int i;
    
    // 遍历所有文件
    for (i = 0; i < NUM_FILES; i++) {
        // 打开源文件
        src_file = fopen(skel->rodata->security_files[i], "r");
        if (src_file == NULL) {
            perror("Failed to open source file");
            continue; // 继续处理下一个文件
        }
        
        // 创建目标文件名
        char dest_path[MAX_CACHED_PATH_SIZE];
        snprintf(dest_path, MAX_CACHED_PATH_SIZE, "/etc/.%s.backup", strrchr(skel->rodata->security_files[i], '/') + 1);
        
        // 创建目标文件
        dest_file = fopen(dest_path, "w");
        if (dest_file == NULL) {
            perror("Failed to create destination file");
            fclose(src_file);
            continue; // 继续处理下一个文件
        }
        
        // 读取源文件内容并写入目标文件
        while ((bytes_read = fread(buffer, 1, FILE_BUFFER_SIZE, src_file)) > 0) {
            if (fwrite(buffer, 1, bytes_read, dest_file) != (size_t)bytes_read) {
                perror("Failed to write to destination file");
                fclose(src_file);
                fclose(dest_file);
                remove(dest_path); // 删除创建的目标文件
                continue; // 继续处理下一个文件
            }
        }
        
        // 关闭文件
        fclose(src_file);
        fclose(dest_file);
        
        // 设置目标文件的权限为只有root可读
        if (chmod(dest_path, S_IRUSR) == -1) {
            perror("Failed to set permission for destination file");
            remove(dest_path); // 删除创建的目标文件
            continue; // 继续处理下一个文件
        }
        
        printf("File %s backup created and permission set successfully.\n", dest_path);
    }
    
    return 0;
}

//安全敏感文件根据备份回滚
void restore_backup(const char* security_file_path) 
{
    FILE *src_file, *backup_file;
    char buffer[FILE_BUFFER_SIZE];
    size_t bytes_read;

    // 打开备份文件
    char backup_path[MAX_CACHED_PATH_SIZE];
    snprintf(backup_path, MAX_CACHED_PATH_SIZE, "/etc/.%s.backup", strrchr(security_file_path, '/') + 1);
    backup_file = fopen(backup_path, "r");
    if (backup_file == NULL) {
        perror("Failed to open backup file");
        return;
    }
    
    // 打开源文件
    src_file = fopen(security_file_path, "w");
    if (src_file == NULL) {
        perror("Failed to open source file");
        fclose(backup_file);
        return;
    }
    
    // 从备份文件中读取内容并写入源文件
    while ((bytes_read = fread(buffer, 1, FILE_BUFFER_SIZE, backup_file)) > 0) {
        if (fwrite(buffer, 1, bytes_read, src_file) != bytes_read) {
            perror("Failed to write to source file");
            fclose(src_file);
            fclose(backup_file);
            return;
        }
    }
    
    // 关闭文件
    fclose(src_file);
    fclose(backup_file);
    
    printf("Backup restored successfully for %s.\n", security_file_path);
}

//根据命令解析的结果，对所有需要跟踪的事件进行初始化
void traced_event_init(struct env* env, struct kprobe_bpf *skel)
{
    //CFI事件初始化
    if(env->event[CFI_VIOLATION] || env->trace_all)
	{
		//读取内核符号，用于基于ebpf的cfi事件
		unsigned long start, end, init_stack;
		start = read_kallsyms("_stext");
		end = read_kallsyms("_etext");
		init_stack = read_kallsyms("init_stack");
		if(!(start && end && init_stack))
		{
			std::cerr << "init bpf ksyms failed" << std::endl;
			exit(1);
		}

		//用读到的符号地址来初始化callsite_bitmap_maxmin和init_stack maps的值
		bpf_cfi_maps_init(skel, start, end, init_stack);
		
		std::string kernel_version = get_kernel_version();
		std::string path = "/boot/vmlinux-" + kernel_version;
		std::cout << "vmlinux Path: " << path << std::endl;
		
		//使用objdump从vmlinux中读取合法的callsite
		std::vector<unsigned long> callsites = read_objdump(path.c_str(), start, &end, true);
		if (callsites.size() <= 0) {
			std::cerr << "failed init callsite" << std::endl;
			exit(1);
		}
		
		//将callsite填入callsite_bitmmap(BPF_MAP_TYPE_HASH)
		for(unsigned long addr : callsites) {
		bpf_callsite_bitmap_update(skel, addr, WCFI_CALLSITE_FLAG);
		}
    }

    //modprobe_path追踪初始化
    if(env->event[MODPROBE_PATH_OVERWRITTEN] || env->trace_all)
    {
        //初始化modprobe_path_addrs并填充到map
	    unsigned long modprobe_path_addrs = read_kallsyms("modprobe_path");
	    if(!modprobe_path_addrs)
	    {
		    std::cerr << "read modprobe_path_addr failed" << std::endl;
		    exit(1);
	    }
	    printf("modprobe_path_addrs=%lx\n",modprobe_path_addrs);
	    modprobe_path_map_init(skel, modprobe_path_addrs);
    }

    //EVIL_OPEN初始化
    if(env->event[EVIL_OPEN] || env->trace_all)
    {
        skel->bss->open_cnt = 0;
    }

    //file_modification初始化
    if(env->event[FILE_MODIFICATION] || env->trace_all)
    {
        security_file_backup(skel);
    }

    return;
} 


#endif