#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <Windows.h>
#include <winioctl.h>
#endif
#include <ifdef.h>

struct PacketDriverStats {
	ULONGLONG receivedPackets = 0; // does not include dropped packets and ignored fragments
	ULONGLONG receivedBytes = 0; // does not include bytes of dropped packets and ignored fragments
	ULONGLONG receivedDroppedPackets = 0;
	ULONGLONG ignoredFragments = 0;
	ULONGLONG sentPackets = 0; // does not include dropped or failed packets
	ULONGLONG sentBytes = 0; // does not include bytes of dropped or failed packets
	ULONGLONG sentFailedPackets = 0;
	ULONGLONG sentDroppedPackets = 0;
};

#ifdef _KERNEL_MODE
#define PACKETDRIVER_DEVICE LR"(\Device\PacketDriver)"
#define PACKETDRIVER_TAG 'DtkP'
#else
#define PACKETDRIVER_DEVICE LR"(\\.\GLOBALROOT\Device\PacketDriver)"
#endif
#define PACKETDRIVER_DEVICE_TYPE FILE_DEVICE_UNKNOWN

constexpr GUID PacketDriverInboundCalloutGuid = {
	0x0e0b747f,
	0x570c,
	0x47c7,
	{0xb8, 0x03, 0x0e, 0x2b, 0x05, 0xe8, 0x77, 0x3c}
};

constexpr GUID PacketDriverOutboundCalloutGuid = {
	0xa0875077,
	0x9ceb,
	0x479e,
	{0x98, 0x08, 0x6a, 0x69, 0x62, 0xb0, 0xfa, 0x98}
};

constexpr size_t maxReadStoredPackets = 1000;
constexpr size_t maxReadStoredBytes = 1500 * maxReadStoredPackets;
constexpr size_t maxWriteStoredPackets = 1000;
constexpr size_t maxWriteStoredBytes = 1500 * maxWriteStoredPackets;

/* Format of data read from / written to the device:
 * +---------------+---------------+-----+---------------+-----------+-----------+-----+---------------+
 * | PacketInfo[0] | PacketInfo[1] | ... | PacketInfo[n] | packet[0] | packet[1] | ... | packet[n - 1] |
 * | .size > 0     | .size > 0     | ... | .size == 0    |           |           |     |               |
 * +---------------+---------------+-----+---------------+-----------+-----------+-----+---------------+
 */
struct PacketInfo {
	enum class Direction {
		Send,
		Receive,
	};
	Direction direction;
	COMPARTMENT_ID compartment;
	IF_INDEX interfaceIdx;
	IF_INDEX subinterfaceIdx;
	size_t size;
	PVOID checksumInfo;
};

#define IOCTL_PACKETDRIVER_GET_STATS CTL_CODE(PACKETDRIVER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_PACKETDRIVER_GET_AND_RESET_STATS CTL_CODE(PACKETDRIVER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_PACKETDRIVER_RESET_STATS CTL_CODE(PACKETDRIVER_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_PACKETDRIVER_WATCH CTL_CODE(PACKETDRIVER_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_PACKETDRIVER_FILTER CTL_CODE(PACKETDRIVER_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA)