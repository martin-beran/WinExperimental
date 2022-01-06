#pragma once

#include <chrono>
#include <optional>
#include <string_view>

class PCapFile {
public:
	PCapFile(const std::wstring_view fileName): fileName(fileName) {}
	PCapFile(const PCapFile&) = delete;
	PCapFile(PCapFile&&) = delete;
	PCapFile& operator=(const PCapFile&) = delete;
	PCapFile&& operator=(PCapFile&&) = delete;
	~PCapFile();
	void create();
	void close();
	void writePacket(const std::string_view data, std::optional<std::chrono::system_clock::time_point);
private:
	std::wstring fileName;
	HANDLE fh = INVALID_HANDLE_FILE;
};