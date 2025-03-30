# ifndef VMLINUX_FLAVORS_H
# define VMLINUX_FLAVORS_H

#define S_IFMT   00170000 // 文件类型的位掩码，用于获取文件类型的部分。
#define S_IFSOCK 0140000  // 套接字文件
#define S_IFLNK  0120000  // 符号链接文件
#define S_IFREG  0100000  // 普通文件
#define S_IFBLK  0060000  // 块设备文件
#define S_IFDIR  0040000  // 目录文件
#define S_IFCHR  0020000  // 字符设备
#define S_IFIFO  0010000  // 命名管道（FIFO）文件

// kernel >= v6.6 inode i_ctime field change
struct inode___older_v66 { 
    struct timespec64 i_ctime;
};

// kernel >= v6.11 inode i_ctime field change
struct inode___older_v611 {
    struct timespec64 __i_ctime;
};

# endif