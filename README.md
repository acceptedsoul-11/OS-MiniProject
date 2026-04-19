# OS-MiniProject

A lightweight Linux container runtime in C with a user-space supervisor and a kernel-space memory monitor.

## What’s Included

- `boilerplate/engine.c`: supervisor runtime, CLI control path, container launch, logging pipeline
- `boilerplate/monitor.c`: Linux kernel module for soft/hard memory-limit enforcement
- `boilerplate/monitor_ioctl.h`: shared ioctl definitions
- `boilerplate/memory_hog.c`: memory-pressure workload
- `boilerplate/cpu_hog.c`: CPU-bound workload
- `boilerplate/io_pulse.c`: I/O-oriented workload
- `boilerplate/Makefile`: build targets for user-space binaries and kernel module

## Features

- Long-running supervisor with `start`, `run`, `ps`, `logs`, and `stop`
- UNIX domain socket control plane
- `clone()`-based container launch with PID, UTS, and mount namespace isolation
- Per-container log capture with a bounded-buffer producer/consumer pipeline
- Kernel monitor with soft-limit warnings and hard-limit kill enforcement
- Graceful fallback when `/dev/container_monitor` is not loaded yet

## Build

Use an Ubuntu 22.04 or 24.04 VM.

```bash
cd boilerplate
make
```

## Basic Run Flow

```bash
cd boilerplate
sudo insmod monitor.ko

mkdir -p ../rootfs-base
wget -O /tmp/alpine.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
sudo tar -xzf /tmp/alpine.tar.gz -C ../rootfs-base

cp -a ../rootfs-base ../rootfs-alpha
cp -a ../rootfs-base ../rootfs-beta
cp ./memory_hog ./cpu_hog ./io_pulse ../rootfs-alpha/
cp ./memory_hog ./cpu_hog ./io_pulse ../rootfs-beta/

sudo ./engine supervisor ../rootfs-base
```

In another terminal:

```bash
cd boilerplate
sudo ./engine start alpha ../rootfs-alpha "/memory_hog 8 500" --soft-mib 32 --hard-mib 64
sudo ./engine start beta ../rootfs-beta "/cpu_hog 20" --nice 5
sudo ./engine ps
sudo ./engine logs alpha
dmesg | tail -n 30
sudo ./engine stop alpha
sudo ./engine stop beta
```

## Notes

- This project is meant to be run inside a Linux VM, not on Windows or WSL.
- Kernel-module loading and namespace operations require root privileges in the VM.
