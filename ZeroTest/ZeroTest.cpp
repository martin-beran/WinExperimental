#define NOMINMAX

#include "ZeroDriver/Driver.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

enum class Mode {
	Read,
	Write,
	ReadWrite,
};

int usage(char* argv0)
{
	std::cerr << "usage: " << argv0 <<
		R"({r|w|rw} BLOCK_SIZE BLOCK_COUNT [FILLER MAX]

Mode:
    r           ... read from driver
    w           ... write to driver
    rw          ... read and write

Parameters:
    BLOCK_SIZE  ... size of a single read/write
    BLOCK_COUNT ... number of reads/writes
    FILLER      ... filler byte value 0-255 (default 0)
    MAX         ... maximum block size accepted/produced by the driver;
                    bigger read buffer will produce partially filled buffer,
                    bigger writes will produce partial writes
                    (default -1 = unlimited)
)";
	return EXIT_FAILURE;
}

int errorMessage(const char* msg, DWORD err)
{
	LPTSTR errMsg = nullptr;
	std::wcerr << "ERROR " << err << ": " << msg;
	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr, err,
		LocaleNameToLCID(L"en-US", 0), reinterpret_cast<LPWSTR>(&errMsg), 0, nullptr) > 0)
	{
		std::unique_ptr<TCHAR, decltype(&LocalFree)> pErrMsg{errMsg, &LocalFree};
		std::wcerr << ": " << errMsg;
	} else
		std::cerr << '\n';
	return EXIT_FAILURE;
}

int main(int argc, char* argv[])
{
	// Process command line
	if (argc != 4 && argc != 6)
		return usage(argv[0]);
	Mode mode;
	using namespace std::literals;
	if (std::string(argv[1]) == "r"s)
		mode = Mode::Read;
	else if (std::string(argv[1]) == "w"s)
		mode = Mode::Write;
	else if (std::string(argv[1]) == "rw"s)
		mode = Mode::ReadWrite;
	else {
		std::cerr << "Invalid mode\n\n";
		return usage(argv[0]);
	}
	bool ok = true;
	unsigned long blockSize = 0;
	unsigned long blockCount = 0;
	std::optional<char> filler;
	std::optional<long long> max;
	try {
		blockSize = std::stoul(argv[2]);
		blockCount = std::stoul(argv[3]);
		if (argc == 6) {
			filler = std::stoi(argv[4]);
			if (filler < 0 || filler > 255)
				ok = false;
			max = std::stoll(argv[5]);
		}
	} catch (const std::invalid_argument&) {
		ok = false;
	} catch (const std::out_of_range&) {
		ok = false;
	}
	if (!ok)
		return usage(argv[0]);
	std::cout <<
		"mode=";
	switch (mode) {
	case Mode::Read:
		std::cout << "r\n";
		break;
	case Mode::Write:
		std::cout << "w\n";
		break;
	case Mode::ReadWrite:
		std::cout << "rw\n";
		break;
	default:
		std::cout << "?\n";
		break;
	}
	std::cout <<
		"blockSize=" << blockSize << '\n' <<
		"blockCount=" << blockCount << '\n' <<
		"filler=";
	if (filler)
		std::cout << unsigned(*filler) << '\n';
	else
		std::cout << "default\n";
	std::cout << "max=";
	if (max)
		std::cout << *max << '\n';
	else
		std::cout << "unlimited\n";
	// Open and configure device
	// Always open for R/W, because it is required by IOCTL
	HANDLE fh = CreateFile(ZERODRIVER_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (fh == INVALID_HANDLE_VALUE)
		return errorMessage("Cannot open device", GetLastError());
	if (DWORD ret;
		filler && !DeviceIoControl(fh, IOCTL_ZERODRIVER_SET_FILLER, &*filler, sizeof(*filler), nullptr, 0, &ret, nullptr))
	{
		return errorMessage("IOCTL_ZERODRIVER_SET_FILLER failed", GetLastError());
	}
	if (DWORD ret; (mode == Mode::Read || mode == Mode::ReadWrite) && max &&
		!DeviceIoControl(fh, IOCTL_ZERODRIVER_SET_MAX_READ, &*max, sizeof(*max), nullptr, 0, &ret, nullptr))
	{
		return errorMessage("IOCTL_ZERODRIVER_SET_MAX_READ failed", GetLastError());
	}
	if (DWORD ret; (mode == Mode::Write || mode == Mode::ReadWrite) && max &&
		!DeviceIoControl(fh, IOCTL_ZERODRIVER_SET_MAX_WRITE, &*max, sizeof(*max), nullptr, 0, &ret, nullptr))
	{
		return errorMessage("IOCTL_ZERODRIVER_SET_MAX_WRITE failed", GetLastError());
	}
	if (DWORD ret; !DeviceIoControl(fh, IOCTL_ZERODRIVER_RESET_STATS, nullptr, 0, nullptr, 0, &ret, nullptr))
		return errorMessage("IOCTL_ZERODRIVER_RESET_STATS failed", GetLastError());
	// Use device
	int result = EXIT_SUCCESS;
	auto beginTime = std::chrono::steady_clock::now();
	std::vector<char> buffer(blockSize);
	size_t expect = buffer.size();
	if (max && max >= 0 && *max < decltype(*max)(expect))
		expect = *max;
	std::cout << "Running..." << std::endl;
	for (unsigned long block = 0; block < blockCount; ++block) {
		if (mode == Mode::Read || mode == Mode::ReadWrite) {
			DWORD rd;
			if (!ReadFile(fh, buffer.data(), DWORD(buffer.size()), &rd, nullptr)) {
				result = errorMessage("ReadFile failed", GetLastError());
				break;
			}
			if (rd != expect) {
				std::cerr << "Read " << rd << " bytes, expected " << expect << std::endl;
				result = EXIT_FAILURE;
				break;
			}
			if (filler) {
				for (size_t i = 0; i < expect; ++i)
					if (buffer[i] != *filler) {
						std::cerr << "Read byte " << unsigned(buffer[i]) << " expected " << unsigned(*filler) <<
							" at index " << i << std::endl;
						result = EXIT_FAILURE;
						goto end;
					}
			}
		}
		if (mode == Mode::Write || mode == Mode::ReadWrite) {
			DWORD wr;
			if (!WriteFile(fh, buffer.data(), DWORD(buffer.size()), &wr, nullptr)) {
				result = errorMessage("WriteFile failed", GetLastError());
				break;
			}
			if (wr != expect) {
				std::cerr << "Written " << wr << " bytes, expected " << expect << std::endl;
				result = EXIT_FAILURE;
				break;
			}
		}
	}
end:
	std::cout << "Done" << std::endl;
	auto endTime = std::chrono::steady_clock::now();
	// Final report
	ZeroDriverStats stats;
	if (DWORD ret; !DeviceIoControl(fh, IOCTL_ZERODRIVER_GET_STATS, nullptr, 0, &stats, sizeof(stats), &ret, nullptr))
		return errorMessage("IOCTL_ZERODRIVER_GET_STATS failed", GetLastError());
	else
		if (ret != sizeof(stats)) {
			std::cerr << "Read " << ret << " bytes of stats, expected " << sizeof(stats) << std::endl;
			return EXIT_FAILURE;
		}
	std::cout <<
		"readRequests=" << stats.readRequests << '\n' <<
		"readBytes=" << stats.readBytes << '\n' <<
		"writeRequests=" << stats.writeRequests << '\n' <<
		"writeBytes=" << stats.writeBytes << std::endl;
	using FpSeconds = std::chrono::duration<double, std::chrono::seconds::period>;
	static_assert(std::chrono::treat_as_floating_point_v<FpSeconds::rep>);
	auto duration = std::chrono::duration_cast<FpSeconds>(endTime - beginTime);
	std::cout << "time=" << std::fixed << std::setprecision(3) << duration.count() << std::endl;
	std::cout << "req/s=" << (std::max(stats.readRequests, stats.writeRequests) / duration.count()) <<std::endl;
	double value = std::max(stats.readBytes, stats.writeBytes) / duration.count();
	std::cout << "bytes/s=" << value << " (" << (value / 1024 / 1024) << "MB/s)" << std::endl;
	value *= 8;
	std::cout << "bits/s=" << value << " (" << (value / 1024 / 1024) << "Mb/s)" << std::endl;
	if (!CloseHandle(fh))
		return errorMessage("Cannot close device", GetLastError());
	return result;
}