import subprocess


file_location = "./comp1/step3/ebpf-runner.py"
runs = 100

for _ in range(runs):
    r = subprocess.run(
        file_location, capture_output=False 
    )
