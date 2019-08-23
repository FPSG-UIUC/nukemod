This is the kernel module used for the APA controlled side channel attack.
NOTE: before using this code, install and boot this kernel https://bitbucket.org/ricpacca/kernel-for-nukemod

Furthermore, make sure to add the kernel boot parameters `nosmap` `transparent_hugepage=never`.
This can be done by modifying a line in the file `/etc/default/grub`:

```sh
GRUB_CMDLINE_LINUX_DEFAULT="nosmap transparent_hugepage=never"
```