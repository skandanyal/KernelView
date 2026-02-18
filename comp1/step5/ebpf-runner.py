from bcc import BPF
import os
import time

bpf = BPF(src_file="ebpf-probe.c")

try:
    while True:
        # Update every second
        time.sleep(1)
        
        # Clear terminal for dashboard effect
        os.system('clear')
        
        print("="*60)
        print(" KERNELVIEW: LIVE FILE ACTIVITY PROFILER")
        print(" Target: results100.txt")
        print("="*60)
        print(f"{'PID':<10} {'PROCESS NAME':<20} {'ACCUMULATED READ (KB)':<20}")
        print("-" * 60)

        stats_map = bpf["live_stats"]
        for k, v in stats_map.items():
            # Convert bytes to KB for better readability
            kb_read = v.total_bytes / 1024
            print(f"{k.value:<10} {v.comm.decode():<20} {kb_read:<20.2f}")

        if not stats_map:
            print("\n[Waiting for file access...]")

except KeyboardInterrupt:
    print("\nShutting down KernelView...")
