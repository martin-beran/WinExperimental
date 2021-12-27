#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#endif

struct PacketDriverStats {
	ULONGLONG receivedPackets = 0;
	ULONGLONG receivedBytes = 0;
	ULONGLONG sentPackets = 0;
	ULONGLONG sentBytes = 0;
	ULONGLONG droppedPackets = 0;
};

#ifdef _KERNEL_MODE
#define PACKETDRIVER_DEVICE LR"(\Device\PacketDriver)"
#else
#define PACKETDRIVER_DEVICE LR"(\\.\GLOBALROOT\Device\PacketDriver)"
#endif
#define PACKETDRIVER_DEVICE_TYPE FILE_DEVICE_UNKNOWN

constexpr GUID PacketDriverCalloutGuid = {
	0x0e0b747f,
	0x570c,
	0x47c7,
	{0xb8, 0x03, 0x0e, 0x2b, 0x05, 0xe8, 0x77, 0x3c}
};

#define IOCTL_PACKETDRIVER_GET_STATS CTL_CODE(PACKETDRIVER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_PACKETDRIVER_GET_AND_RESET_STATS CTL_CODE(PACKETDRIVER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_PACKETDRIVER_RESET_STATS CTL_CODE(PACKETDRIVER_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)