# -*- coding: utf-8 -*-
"""GPU pre-flight check for the run packages: exit code 0 only if PyTorch can train on the NVIDIA GPU.

Prints the PyTorch / CUDA versions and the device, runs a small matrix product and a backward pass on the GPU,
and reports the GPU memory in use. Used by runs/P5c_gpu.ps1 before every training step.
"""
import sys
import time

import torch

ok = torch.cuda.is_available()
print(f'[gpu] torch {torch.__version__}, CUDA {torch.version.cuda}, cuda available: {ok}', flush=True)
if not ok:
    print('[gpu] ERROR: CUDA is not available - check the NVIDIA driver, the charger (battery mode can switch the '
          'GPU off) and the MyProject environment.', flush=True)
    sys.exit(1)
dev = torch.device('cuda:0')
print(f'[gpu] device: {torch.cuda.get_device_name(0)} (compute {".".join(map(str, torch.cuda.get_device_capability(0)))})',
      flush=True)
t0 = time.perf_counter()
x = torch.randn(4096, 4096, device=dev, requires_grad=True)
y = (x @ x).relu().sum()
y.backward()
torch.cuda.synchronize()
print(f'[gpu] test matmul + backward on the GPU: ok ({1000 * (time.perf_counter() - t0):.0f} ms), '
      f'memory allocated {torch.cuda.memory_allocated(0) / 2**20:.0f} MiB', flush=True)
sys.exit(0)
