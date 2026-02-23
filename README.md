# KernelView
System call activity monitoring and Process behavior visualizer.

## Contents

### Compartment 1
**Reference video:** ![Building eBPF Programs - Linux Observability](https://youtu.be/CprgVJeJ-04?si=oKog1S9Tx-kgKT3f)

**Step_1:** Prints "Hello there!" everytime a process is created.    
**Step_2:** Prints the PID of the new processes created.    
**Step_3:** Prints the PID of processes which perform `open()` function.     
**Step_4:** Prints the PID of processes which perform `read()` function.

### System-call Monitor 
To use the Sys_call monitor, follow the steps below:
```bash
cd Final
sudo python3 ebpf-runner.py 
```
A dashboard runs in the terminal showing the process names, along with the operation performed.

