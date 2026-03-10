// token_protect.bpf.c — eBPF LSM program to protect the sandbox bypass token
//
// Denies read access to a specific file (by device + inode) for any process
// with PR_SET_NO_NEW_PRIVS set. All three sandbox backends (bwrap, firejail,
// landlock) set this irrevocable kernel flag, so this program blocks all
// sandboxed processes from reading the token — regardless of filesystem
// permissions.
//
// Build:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   clang -g -O2 -target bpf -D__TARGET_ARCH_$(uname -m) \
//       -I. -I/usr/include/bpf \
//       -c token_protect.bpf.c -o token_protect.bpf.o
//
// Load (autoattach to LSM hook):
//   bpftool prog loadall token_protect.bpf.o /sys/fs/bpf/token_protect autoattach
//
// Set the protected file identity (device + inode).
// IMPORTANT: the kernel s_dev uses new_encode_dev() format, not the old
// encoding from stat(2). Convert via: (major << 20) | minor.
//   TOKEN_INO=$(stat -c %i /etc/slurm/.sandbox-bypass-token)
//   TOKEN_DEV=$(python3 -c "import os; st = os.stat('/etc/slurm/.sandbox-bypass-token'); print((os.major(st.st_dev) << 20) | os.minor(st.st_dev))")
//   MAP_ID=$(bpftool map show | grep protected_file | head -1 | awk '{print $1}' | tr -d ':')
//   DEV_BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_DEV)))")
//   INO_BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_INO)))")
//   bpftool map update id $MAP_ID key 0x00 0x00 0x00 0x00 value $DEV_BYTES $INO_BYTES
//
// Requires:
//   - Kernel >= 5.7 with CONFIG_BPF_LSM=y
//   - "bpf" in the LSM list (boot param: lsm=...,bpf)
//   - clang, llvm, libbpf-dev, bpftool
//
// See ADMIN_HARDENING.md §1 for the full design.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// PFA_NO_NEW_PRIVS is bit 0 in task_struct->atomic_flags
#define PFA_NO_NEW_PRIVS 0

// Identity of the protected token file (device + inode).
// Inode numbers are only unique within a filesystem, so we also check
// the device to avoid false positives on other filesystems.
struct file_id {
    __u64 dev;
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct file_id);
} protected_file SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(deny_token_read, struct file *file)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Check if the process has no_new_privs set
    unsigned long aflags = BPF_CORE_READ(task, atomic_flags);
    if (!(aflags & (1UL << PFA_NO_NEW_PRIVS)))
        return 0;  // Not sandboxed — allow

    // Look up the protected file identity
    __u32 key = 0;
    struct file_id *target = bpf_map_lookup_elem(&protected_file, &key);
    if (!target)
        return 0;

    // Compare device and inode
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    unsigned long file_ino = BPF_CORE_READ(inode, i_ino);
    dev_t file_dev = BPF_CORE_READ(inode, i_sb, s_dev);

    if ((__u64)file_dev == target->dev && file_ino == target->ino) {
        bpf_printk("token_protect: DENIED (pid=%d, dev=%u, ino=%lu)",
                    bpf_get_current_pid_tgid() >> 32, file_dev, file_ino);
        return -13;  // -EACCES
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
