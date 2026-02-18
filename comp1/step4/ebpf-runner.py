from bcc import BPF
from pathlib import Path

def print_read_event(cpu, data, size):
    event = bpf["read_events"].event(data)
    print(f"TARGET MATCH | Process: {event.comm.decode():<10} | PID: {event.pid:<6} | Read: {event.count} bytes")

# Load the C source correctly
bpf_source = Path('ebpf-probe.c').read_text()
bpf = BPF(text=bpf_source)

bpf["read_events"].open_perf_buffer(print_read_event)

print("Monitoring specifically for 'results100.txt' activity...")
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
