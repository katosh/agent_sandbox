// token_protect.bpf.c — eBPF LSM program to protect the sandbox bypass token
//
// Denies read access to a specific file (by inode) for any process with
// PR_SET_NO_NEW_PRIVS set. Both bwrap and Landlock sandbox backends set
// this irrevocable kernel flag, so this program blocks all sandboxed
// processes from reading the token — regardless of filesystem permissions.
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
// Set the protected inode:
//   TOKEN_INO=$(stat -c %i /etc/slurm/.sandbox-bypass-token)
//   MAP_ID=$(bpftool map show | grep protected_inode | awk '{print $1}' | tr -d ':')
//   BYTES=$(python3 -c "import struct; print(' '.join(f'0x{x:02x}' for x in struct.pack('<Q', $TOKEN_INO)))")
//   bpftool map update id $MAP_ID key 0x00 0x00 0x00 0x00 value $BYTES
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

// Map holding the inode number of the protected token file.
// Set at load time via bpftool map update.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} protected_inode SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(deny_token_read, struct file *file)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Check if the process has no_new_privs set
    unsigned long aflags = BPF_CORE_READ(task, atomic_flags);
    if (!(aflags & (1UL << PFA_NO_NEW_PRIVS)))
        return 0;  // Not sandboxed — allow

    // Compare file inode against the protected token
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    unsigned long file_ino = BPF_CORE_READ(inode, i_ino);

    __u32 key = 0;
    __u64 *target_ino = bpf_map_lookup_elem(&protected_inode, &key);
    if (!target_ino)
        return 0;

    if (file_ino == *target_ino) {
        bpf_printk("token_protect: DENIED (pid=%d, ino=%lu)",
                    bpf_get_current_pid_tgid() >> 32, file_ino);
        return -13;  // -EACCES
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
