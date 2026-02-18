# KernelView
System call activity monitoring and Process behavior visualizer.

## Contents

### Compartment 1
**Reference video:** ![Building eBPF Programs - Linux Observability](https://youtu.be/CprgVJeJ-04?si=oKog1S9Tx-kgKT3f)

**Step_1:** Prints "Hello there!" everytime a process is created.    
**Step_2:** Prints the PID and PPID of the new processes created.    
**Step_3:** Prints the PID and PPID of processes which perform `open()` function.     
**Step_4:** Prints the PID and PPID of processes which perform `read()` function.     
**Step_5:** Terminal based dashboard to display PID and PPID of processes which perform `open()` or `read()` function.    

