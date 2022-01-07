#pragma once

#include <windows.h>

#include <chrono>
#include <stdexcept>
#include <optional>
#include <string_view>

class PCapFileError: std::runtime_error {
public:
	PCapFileError(const char* msg, DWORD error): runtime_error(createMessage(msg, error)) {}
private:
	static std::string createMessage(const char* msg, DWORD error);
};

class PCapFile {
public:
	PCapFile() = default;
	PCapFile(const std::wstring_view fileName): fileName(fileName) {}
	PCapFile(const PCapFile&) = delete;
	PCapFile(PCapFile&& o) {
		std::swap(fileName, o.fileName);
		std::swap(fh, o.fh);
	}
	PCapFile& operator=(const PCapFile&) = delete;
	PCapFile& operator=(PCapFile&& o) {
		if (&o != this) {
			fileName = o.fileName;
			o.fileName.clear();
			fh = o.fh;
			o.fh = INVALID_HANDLE_VALUE;
		}
		return *this;
	}
	~PCapFile();
	void create();
	void close();
	void writePacket(const std::string_view data, std::optional<std::chrono::system_clock::time_point>);
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
	std::wstring fileName;
	HANDLE fh = INVALID_HANDLE_VALUE;
};