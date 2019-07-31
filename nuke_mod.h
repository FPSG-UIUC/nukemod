#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

#define MAJOR_NUM 1313

#define IOCTL_SET_MSG _IOR(MAJOR_NUM, 0, char *)

#define IOCTL_SET_NUKE_ADDR _IOR(MAJOR_NUM, 1, char *)

#define IOCTL_SET_MONITOR_ADDR _IOR(MAJOR_NUM, 2, char *)

#define IOCTL_PREP_PF _IOR(MAJOR_NUM, 3, char *)

#define IOCTL_LONG_LATENCY _IOR(MAJOR_NUM, 4, char *)

#define DEVICE_FILE_NAME "nuke_channel"
#define DEVICE_FILE_NAME_PATH "/home/riccardo/nukemod/nuke_channel"

enum call_type { MSG,
				 NUKE_ADDR,
				 MONITOR_ADDR,
				 PF,
                 LONG_LATENCY };

#endif
