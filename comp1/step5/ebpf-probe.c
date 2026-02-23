#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct data_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  char fname[256];
  char op[16];
};

BPF_HASH(stats_map, u32, struct data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct data_t data = {};

  data.pid = pid;
  // REMOVED: data.type = 0; (This was causing the compilation error)
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  bpf_probe_read_user(&data.fname, sizeof(data.fname), args->filename);
  __builtin_memcpy(data.op, "OPEN", 5);

  stats_map.update(&pid, &data);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct data_t data = {};

  data.pid = pid;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  __builtin_memcpy(data.fname, "-", 2);
  __builtin_memcpy(data.op, "READ", 5);

  stats_map.update(&pid, &data);
  return 0;
}
