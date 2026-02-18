from bcc import BPF 
from pathlib import Path 
import time 

def clone_process_event(cpu, data, size):
    event = bpf["clone_events"].event(data)
    print(f"Process {event.comm.decode()} (PID: {event.pid}, PPID: {event.ppid}) called sys_clone")
    
def open_process_event(cpu, data, size):
    event = bpf['open_events'].event(data)
    print(f"[{event.timestamp / 1e9:.5f}] Process: {event.comm.decode()} (PID: {event.pid}) Opened file: {event.filename.decode()}")

bpf_source = Path('ebpf-probe.c').read_text()
bpf = BPF(text=bpf_source)

bpf['clone_events'].open_perf_buffer(clone_process_event)
bpf['open_events'].open_perf_buffer(open_process_event)
print("Monitoring sys_clone events...")


# track 100 iterations of compilation
start_time = time.time()
duration = 100 # Adjust this based on how long 100 gcc commands take

try:
    while time.time() - start_time < duration:
        # Poll all buffers for events
        bpf.perf_buffer_poll(timeout=100) 
except KeyboardInterrupt:
    pass
