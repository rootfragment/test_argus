# Argus - Kernel-Space Rootkit Detection Module

This directory contains the source code for the Argus Loadable Kernel Module (LKM), a security tool designed to provide a trusted, low-level view of system resources. It is the core kernel-space component of the Argus framework, responsible for gathering data that can be used to detect hidden processes, modules, and network connections indicative of a rootkit. This project uses the output of the above said LKMs 
as the ground truth, and thereby cross checking it with the user-space data will provide insights on hidden processes, modules or sockets. 

## Features

The Argus LKM provides the underlying data for:

- **Process Enumeration:** Traverses the kernel's internal process list to create a complete snapshot of all running tasks.
- **Module Enumeration:** Lists all currently loaded kernel modules from the kernel's own perspective.
- **Network Socket Enumeration:** Identifies all active TCP and UDP sockets by inspecting process file descriptors.

## How It Works

When loaded, the Argus LKM (`argus_lkm.ko`) creates a set of read-only files in the `/proc` filesystem. These files serve as an interface for userspace tools to query the kernel's view of the system directly.

- **/proc/rk_ps**: Provides a list of all running processes (PID and command name).
- **/proc/rk_mods**: Provides a list of all loaded kernel modules.
- **/proc/rk_sockets**: Provides a list of all active network sockets, including the process holding them and the port number.

A userspace application can read these files to get a ground-truth view of the system, which can then be compared against the output of standard utilities like `ps`, `lsmod`, and `ss` to identify discrepancies.

## Components

- **`core.c`**: The main entry point for the kernel module. It handles the initialization and cleanup of the `/proc` interface files.
- **`process.c` / `process.h`**: Contains the logic for traversing the kernel's process list (`task_struct`) and exposing it through `/proc/rk_ps`.
- **`modules.c` / `modules.h`**: Contains the logic for traversing the kernel's list of loaded modules and exposing it through `/proc/rk_mods`.
- **`socket.c` / `socket.h`**: Contains the logic for iterating through open file descriptors to find network sockets and exposing them through `/proc/rk_sockets`.
- **`Makefile`**: The build script to compile the source code into a loadable kernel module (`.ko` file).

## Building and Usage

### Prerequisites

You must have the kernel headers for your running kernel version installed. On Debian-based systems, this can be done with:
```bash
sudo apt-get update
sudo apt-get install linux-headers-$(uname -r)
```

### 1. Build the Kernel Module

Run `make` in this directory to compile the LKM:
```bash
make
```
This will produce the `argus_lkm.ko` file.

### 2. Load the Kernel Module

Use `insmod` to load the module into the kernel:
```bash
sudo insmod argus_lkm.ko
```
You can verify that the module is loaded by checking the output of `dmesg` or looking for the `/proc/rk_*` files.

### 3. Unload the Module

When finished, unload the module with `rmmod`:
```bash
sudo rmmod argus_lkm
```

## Disclaimer

This tool is intended for educational and security research purposes. Loading third-party kernel modules can be dangerous and may destabilize your system. Use with caution.
