#include <linux/sched.h>

struct read_data_t {
  u32 pid;
  char comm[TASK_COMM_LEN];
  u64 count;
};

BPF_PERF_OUTPUT(read_events);
// Map to store PIDs that have opened our target file
BPF_HASH(tracked_pids, u32, u8);

// 1. Hook Open to find the target file
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  char filename[NAME_MAX];
  bpf_probe_read_user_str(&filename, sizeof(filename), args->filename);

  // The filename we are looking for
  char target[] = "results100.txt";

  // Simple check: does the filename contain our target string?
  // We use a manual loop because bpf helpers for strstr are limited
  int match = 1;
  for (int i = 0; i < 14; i++) {
    if (filename[i] != target[i]) {
      match = 0;
      break;
    }
  }

  if (match) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 one = 1;
    tracked_pids.update(&pid, &one);
  }
  return 0;
}

// 2. Hook Read to report data ONLY for those PIDs
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // Only proceed if this PID is marked in our map
  u8 *exists = tracked_pids.lookup(&pid);
  if (!exists)
    return 0;

  struct read_data_t data = {};
  data.pid = pid;
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  data.count = args->count;

  read_events.perf_submit(args, &data, sizeof(data));
  return 0;
}
