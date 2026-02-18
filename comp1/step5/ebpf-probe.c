#include <linux/sched.h>

struct stats_t {
  u64 total_bytes;
  char comm[TASK_COMM_LEN];
};

// Map to store aggregated data: Key=PID, Value=Stats
BPF_HASH(live_stats, u32, struct stats_t);
// Internal map to track which PIDs have opened our target file
BPF_HASH(tracked_pids, u32, u8);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  char filename[NAME_MAX];
  bpf_probe_read_user_str(&filename, sizeof(filename), args->filename);

  // TARGET FILTER: Match results100.txt
  char target[] = "results100.txt";
  int match = 0;
  for (int i = 0; i < 32; i++) {
    if (filename[i] == 'r' && filename[i + 1] == 'e' &&
        filename[i + 2] == 's') {
      match = 1;
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

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u8 *tracked = tracked_pids.lookup(&pid);
  if (!tracked)
    return 0;

  struct stats_t *stats, vars = {};
  stats = live_stats.lookup(&pid);
  if (stats) {
    stats->total_bytes += args->count;
  } else {
    vars.total_bytes = args->count;
    bpf_get_current_comm(&vars.comm, sizeof(vars.comm));
    live_stats.update(&pid, &vars);
  }
  return 0;
}
