#pragma once

// Creating PCAP file according to https://wiki.wireshark.org/Development/LibpcapFileFormat

#define NOMINMAX

#include <windows.h>

#include <chrono>
#include <stdexcept>
#include <optional>
#include <string_view>

class PCapFileError: public std::runtime_error {
public:
	PCapFileError(const char* msg, DWORD error): runtime_error(createMessage(msg, error)) {}
private:
	static std::string createMessage(const char* msg, DWORD error);
};

class PCapFile {
public:
	static constexpr uint32_t magicMicroseconds = 0xa1b2c3d4;
	static constexpr uint32_t magicNanoseconds = 0xa1b23c4d;
	static constexpr uint32_t defaultSnaplen = 65535;
	static constexpr uint32_t LINKTYPE_RAW = 101; // raw IP as defined by tcpdump and libpcap
	explicit PCapFile(uint32_t snaplen = defaultSnaplen): snaplen(defaultSnaplen) {}
	explicit PCapFile(const std::wstring_view fileName, uint32_t snaplen = defaultSnaplen):
		fileName(fileName), snaplen(snaplen) {}
	PCapFile(const PCapFile&) = delete;
	PCapFile(PCapFile&& o) noexcept {
		operator=(std::move(o));
	}
	PCapFile& operator=(const PCapFile&) = delete;
	PCapFile& operator=(PCapFile&& o) noexcept {
		if (&o != this) {
			fileName = std::move(o.fileName);
			fh = o.fh;
			o.fh = INVALID_HANDLE_VALUE;
			snaplen = o.snaplen;
			ready = o.ready;
			o.ready = false;
		}
		return *this;
	}
	~PCapFile();
	void create();
	void close();
	void writePacket(const std::string_view data, std::chrono::system_clock::time_point timestamp);
	void writePacket(const std::string_view data);
	bool isReady() const noexcept {
		return ready;
	}
private:
	struct PCapHdr {
		uint32_t magicNumber;
		uint16_t versionMajor;
		uint16_t versionMinor;
		int32_t thiszone;
		uint32_t sigfigs;
		uint32_t snaplen;
		uint32_t network;
	};
	struct PCapRecHdr {
		uint32_t tsSec;
		uint32_t tsUsec;
		uint32_t inclLen;
		uint32_t origLen;
	};
	std::wstring fileName;
	uint32_t snaplen = defaultSnaplen;
	HANDLE fh = INVALID_HANDLE_VALUE;
	bool ready = false;
};