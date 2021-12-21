#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#endif

struct ZeroDriverStats {
	ULONGLONG readRequests = 0;
	ULONGLONG readBytes = 0;
	ULONGLONG writeRequests = 0;
	ULONGLONG writeBytes = 0;
};

#ifdef _KERNEL_MODE
#define ZERODRIVER_DEVICE LR"(\Device\ZeroDriver)"
#else
#define ZERODRIVER_DEVICE LR"(\\.\GLOBALROOT\Device\ZeroDriver)"
#endif
#define ZERODRIVER_DEVICE_TYPE FILE_DEVICE_UNKNOWN

#define IOCTL_ZERODRIVER_SET_MAX_READ CTL_CODE(ZERODRIVER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ZERODRIVER_SET_MAX_WRITE CTL_CODE(ZERODRIVER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ZERODRIVER_SET_FILLER CTL_CODE(ZERODRIVER_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ZERODRIVER_GET_STATS CTL_CODE(ZERODRIVER_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ZERODRIVER_GET_AND_RESET_STATS CTL_CODE(ZERODRIVER_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ZERODRIVER_RESET_STATS CTL_CODE(ZERODRIVER_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_WRITE_DATA)