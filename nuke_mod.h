#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

#define MAJOR_NUM 1315

#define IOCTL_APPEND_ADDR _IOR(MAJOR_NUM, 0, char *)

#define IOCTL_PASS_SPECIAL_ADDR _IOR(MAJOR_NUM, 1, char *)

#define IOCTL_START_MONITORING _IOR(MAJOR_NUM, 2, char *)

#define IOCTL_STOP_MONITORING _IOR(MAJOR_NUM, 3, char *)

#define IOCTL_SIGNAL _IOR(MAJOR_NUM, 4, char *)

#define IOCTL_JOIN _IOR(MAJOR_NUM, 5, char *)

#define DEVICE_FILE_NAME_PATH "/dev/nuke_channel"

enum call_type { APPEND_ADDR,
				 PASS_SPECIAL_ADDR,
				 START_MONITORING,
				 STOP_MONITORING,
				 SIGNAL,
				 JOIN };

#endif
