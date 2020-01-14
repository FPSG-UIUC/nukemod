# Overview

`nukemod` is a kernel module that can be used to perform controlled-channel attacks and to halt / resume user-space threads from the operating system. It is used in the paper:

- _"Game of Threads: Enabling Asynchronous Poisoning Attacks"_ (__ASPLOS 2020__)

In particular, this repository contains the kernel code used in the evaluation of the attack against our SGX proof-of-concept (cf. Section 6 in the paper).
The full code artifact of the paper is available at:

- https://github.com/jose-sv/hogwild_pytorch

# Supported Hardware
We tested this code on a bare-metal machine with an Intel i7-6700K CPU @ 4.00GHz.
We cannot guarantee that it works on other CPUs or in virtualized environments.

# Required Setup
- Ubuntu 16.04 LTS

# Prerequisites
To monitor page-faults, `nukemod` hooks the page fault handler of the Linux kernel.
However, this is not allowed by default in the Linux kernel.
To circumvent this limitation, we minimally modified kernel 4.4.0-101.124 so that it allows to hook the page fault handler.
Here are the instructions to patch and install this kernel.

- Install the required packages by running `sudo apt install -y build-essential ocaml automake autoconf libtool wget python libssl-dev bc`.
- Download Ubuntu kernel 4.4.0-101.124 from here:
  - https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/linux/4.4.0-101.124/linux_4.4.0.orig.tar.gz
- Extract the downloaded kernel into a directory `linux-4.4`.
- Patch the extracted kernel using our provided kernel patch `4.4.0-101.124.patch`. To do this, `cd` into the directory `linux-4.4` and run `patch -p1 < ../4.4.0-101.124.patch`.
- Compile and install the patched kernel. Instructions for this step are available in the README of the kernel itself. In short, you can run:
```sh
cp /boot/config-`uname -r` .config
make -j `nproc` && sudo make modules_install && sudo make install
```
- After installing the custom kernel, make sure to add the kernel boot parameters `nosmap` and `transparent_hugepage=never` to grub.
This can be done by modifying a line in the file `/etc/default/grub`:
```sh
GRUB_CMDLINE_LINUX_DEFAULT="nosmap transparent_hugepage=never"
```
- Run `sudo update-grub` to apply the edits to the configuration.
- Reboot your machine into the custom kernel with the custom configuration.

# Usage
- Compile `nukemod` module by running `make`.
- (optional) Clear the message buffer of the kernel using `sudo dmesg --clear`.
- Create a device file for `nukemod` using `sudo mknod /dev/nuke_channel c 1315 0`.
- Load `nukemod` using `sudo insmod nuke.ko`. You can check if it loaded correctly by running `dmesg`.
- Now you can launch the user-space APA attack from this repo: https://github.com/jose-sv/sgx_scheduling.
The user-space attack code will invoke the functions that are in this module.
- (optional) You can see what the kernel module was doing during the attack using `dmesg`.
- When you are done with the attack, unload the kernel module using `sudo rmmod nuke`.

# Credits
Some of this code is inspired from other repositories:

- https://github.com/heartever/SPMattack
- https://github.com/dskarlatos/MicroScope
