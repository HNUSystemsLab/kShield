# ifndef FILESYSTEM_H
# define FILESYSTEM_H

# include "maps.h"
# include "types.h"
# include "const.h"
# include "buffer.h"
# include "vmlinux_flavors.h"

#define statfunc static __always_inline

//PROTOTYPES
statfunc unsigned short get_inode_mode_from_file(struct file *file); 
statfunc unsigned int get_file_open_mode_from_file(struct file *file);
statfunc struct mount *real_mount(struct vfsmount *mnt);
statfunc struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt);
statfunc struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry);
statfunc struct qstr get_d_name_from_dentry(struct dentry *dentry);
statfunc size_t get_path_str_buf(struct path *path, buf_t *out_buf);
statfunc void *get_path_str(struct path *path);
statfunc u64 get_time_nanosec_timespec(struct timespec64 *ts);
statfunc u64 get_ctime_nanosec_from_inode(struct inode *inode);
statfunc u64 get_ctime_nanosec_from_file(struct file *file);
statfunc dev_t get_dev_from_file(struct file *file);
statfunc unsigned long get_inode_nr_from_file(struct file *file);
statfunc file_id_t get_file_id(struct file *file);
statfunc file_info_t get_file_info(struct file *file);

//FUNCTIONS
statfunc unsigned short get_inode_mode_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode, i_mode);
}

statfunc struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
    // container_of是一个定义在/include/linux/container_of.h的一个宏
    // 它通过结构体成员变量地址获取这个结构体的地址
}

statfunc struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt)
{
    return BPF_CORE_READ(vfsmnt, mnt_root);
}

statfunc struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_parent);
}

statfunc struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return BPF_CORE_READ(dentry, d_name);
}

// Read the file path to the given buffer, returning the start offset of the path.(待移植)
statfunc size_t get_path_str_buf(struct path *path, buf_t *out_buf)
{
    if (path == NULL || out_buf == NULL) {
        return 0;
    }

    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;
    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = get_d_name_from_dentry(dentry);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);// 0x1000
        off = buf_off - len;
        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_str(
                &(out_buf->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *) d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(out_buf->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }
    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(out_buf->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(out_buf->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(out_buf->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }
    //bpf_printk("buf_off %d\n",buf_off);
    return buf_off;
}

statfunc void *get_path_str(struct path *path)
{
    // Get per-cpu string buffer
    buf_t *string_p = get_buf(STRING_BUF_IDX);
    
    if (string_p == NULL)
        return NULL;

    size_t buf_off = get_path_str_buf(path, string_p);
    
    return &string_p->buf[buf_off];
}

statfunc u64 get_time_nanosec_timespec(struct timespec64 *ts)
{
    time64_t sec = BPF_CORE_READ(ts, tv_sec);
    if (sec < 0)
        return 0;

    long ns = BPF_CORE_READ(ts, tv_nsec);

    return (sec * 1000000000L) + ns;
}

statfunc u64 get_ctime_nanosec_from_inode(struct inode *inode)
{
    struct timespec64 ts;
    // bpf_core_field_exists是CO-RE提供的一个辅助函数，具体见 https://www.ebpf.top/post/bpf_core/
    // Kernel 6.6 - 6.10
    if (bpf_core_field_exists(((struct inode___older_v611 *) inode)->__i_ctime)) {
        struct inode___older_v611 *old_inode_v611 = (void *) inode;
        ts = BPF_CORE_READ(old_inode_v611, __i_ctime);
    }
    // Kernel < 6.6
    else {
        struct inode___older_v66 *old_inode_v66 = (void *) inode;
        ts = BPF_CORE_READ(old_inode_v66, i_ctime);
    }

    return get_time_nanosec_timespec(&ts);
}

statfunc u64 get_ctime_nanosec_from_file(struct file *file)
{
    struct inode *f_inode = BPF_CORE_READ(file, f_inode);
    return get_ctime_nanosec_from_inode(f_inode);
}

statfunc dev_t get_dev_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode, i_sb, s_dev);
}

statfunc unsigned long get_inode_nr_from_file(struct file *file)
{
    return BPF_CORE_READ(file, f_inode, i_ino);
}

statfunc file_id_t get_file_id(struct file *file)
{
    file_id_t file_id = {};
    if (file != NULL) {
        file_id.ctime = get_ctime_nanosec_from_file(file);
        file_id.device = get_dev_from_file(file);
        file_id.inode = get_inode_nr_from_file(file);
    }
    return file_id;
}

statfunc file_info_t get_file_info(struct file *file)
{
    file_info_t file_info = {};
    long ret = 0;
    if (file != NULL) {
        // 获取文件id
        file_info.id = get_file_id(file);
        // 获取文件路径名
        file_info.pathname_p = get_path_str(__builtin_preserve_access_index(&file->f_path));
    }

    return file_info;
}

# endif
