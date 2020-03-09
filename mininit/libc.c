#include "syscall_arch.h"
#include <syscall.h>
#include <linux/fcntl.h>

int _close(int fd)
{
	return (int) __syscall1(__NR_close, fd);
}
//
int _open(char *path, int flags)
{
	// only relative path supported
	return (int) __syscall4(__NR_openat, AT_FDCWD, (long) path, flags, 0);
}

//int ioctl(int fd, unsigned long request, ...)
// HACK:
int ioctl(int fd, unsigned long request, void *ptr)
{
	return (int) __syscall3(__NR_ioctl, fd, request, (long) ptr);
}
