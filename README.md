This is the kernel module used for the APA controlled side channel attack.

# Usage
- Before using this code, install this kernel https://bitbucket.org/ricpacca/kernel-for-nukemod.
This can be done following the instructions in that repo.
- After installing the custom kernel, make sure to add the kernel boot parameters `nosmap` `transparent_hugepage=never` to grub.
This can be done by modifying a line in the file `/etc/default/grub`:
```sh
GRUB_CMDLINE_LINUX_DEFAULT="nosmap transparent_hugepage=never"
```
- Reboot your machine into the custom kernel (1) with the custom configuration (2).
- Compile this kernel module by running `make`.
- (optional) Clear the message buffer of the kernel using `sudo dmesg --clear`.
- Load this kernel module using `sudo insmod nuke.ko`. You can check if it loaded correctly by running `dmesg`.
- Now you can launch the user-space APA attack from this repo: https://github.com/jose-sv/sgx_scheduling.
The user-space attack code will invoke the functions that are in this module.
- (optional) You can see what the kernel module was doing during the attack using `dmesg`.
- When you are done with the attack, unload the kernel module using `sudo rmmod nuke`.

# Credits
Some of this code is inspired from other repositories:

- https://github.com/heartever/SPMattack
- https://github.com/dskarlatos/MicroScope