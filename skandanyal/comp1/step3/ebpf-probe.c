#include <bcc/proto.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
  u32 pid;                  // process id
  u32 ppid;                 // parent process id
  char comm[TASK_COMM_LEN]; // process name
};

struct open_data_t {
  u32 pid;
  u64 timestamp;
  char comm[TASK_COMM_LEN];
  char filename[NAME_MAX];
};

BPF_PERF_OUTPUT(clone_events);
BPF_PERF_OUTPUT(open_events); // handles the open() functions recorded

// trace process creation
int kprobe__sys_clone(void *ctx) {
  struct data_t data = {}; // array of structures
  struct task_struct *task;
  struct task_struct *real_parent;

  task = (struct task_struct *)bpf_get_current_task();
  data.pid = bpf_get_current_pid_tgid() >> 32;

  bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);
  bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &real_parent->tgid);
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  clone_events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  struct open_data_t data = {};

  data.pid = bpf_get_current_pid_tgid() >> 32; // get a 32 bit op
  data.timestamp = bpf_ktime_get_ns();
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  bpf_probe_read_user_str(&data.filename, sizeof(data.filename),
                          args->filename);

  open_events.perf_submit(args, &data, sizeof(data));
  return 0;
};
