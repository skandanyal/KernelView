from bcc import BPF 
from pathlib import Path 


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

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
