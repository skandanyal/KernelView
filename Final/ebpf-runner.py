from bcc import BPF
import os
import time

# Initialize BPF
bpf = BPF(src_file="ebpf-probe.c")
stats_map = bpf.get_table("stats_map")

try:
    while True:
        # Update every second
        time.sleep(1)
        
        # Clear terminal for dashboard effect
        os.system('clear')
        
        print("="*80)
        print(" KERNELVIEW: LIVE FILE ACTIVITY PROFILER")
        print("="*80)
        print(f"{'PID':<10} {'PROCESS NAME':<20} {'FILENAME':<30} {'OPERATION':<10}")
        print("-" * 80)

        # Check if map is empty
        if len(stats_map) == 0:
            print("\n[Waiting for file access...]")
        else:
            # Iterate through the hash map and print entries
            # We sort by PID for a stable dashboard view
            for key, val in sorted(stats_map.items(), key=lambda x: x[0].value):
                print(f"{val.pid:<10} {val.comm.decode():<20} {val.fname.decode():<30} {val.op.decode():<10}")

        # Optional: Clear the map after each print to only show "new" activity 
        # since the last refresh. Remove this line if you want a persistent list.
        stats_map.clear()

except KeyboardInterrupt:
    print("\nShutting down KernelView...")
