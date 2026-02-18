int kprobe__sys_clone(void *ctx) {
  bpf_trace_printk("hello there!!\n");
  return 0;
}
