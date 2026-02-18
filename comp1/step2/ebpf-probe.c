#include <bcc/proto.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
  u32 pid;                  // process id
  u32 ppid;                 // parent process id
  char comm[TASK_COMM_LEN]; // process name
};

BPF_PERF_OUTPUT(events);

int kprobe__sys_clone(void *ctx) {
  struct data_t data = {}; // array of structures
  struct task_struct *task;
  struct task_struct *real_parent;

  // get current task structure
  task = (struct task_struct *)bpf_get_current_task();

  // extractPID (TGID) - shift to get the 32-bit PID
  data.pid = bpf_get_current_pid_tgid() >> 32;

  // SAFE ACCESS: Read the pointer to the real_parent task
  bpf_probe_read_kernel(&real_parent, sizeof(real_parent), &task->real_parent);

  // SAFE ACCESS: Read the tgid (pid) from that parent task
  bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &real_parent->tgid);

  // get process name
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
