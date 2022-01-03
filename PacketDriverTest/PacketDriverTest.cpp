#define NOMINMAX

#include "PacketDriver/PacketDriver.h"

#include <fwpmu.h>

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <vector>

// eeadda4d-dc1b-4b94-8da3-3048437e3292
constexpr GUID providerKeyGuid = {
	0xeeadda4d,
	0xdc1b,
	0x4b94,
	{0x8d, 0xa3, 0x30, 0x48, 0x43, 0x7e, 0x32, 0x92}
};

// 48eafe59-4fd5-45fd-98fc-7e0bff2e37e4
constexpr GUID sublayerKeyGuid = {
	0x48eafe59,
	0x4fd5,
	0x45fd,
	{0x98, 0xfc, 0x7e, 0x0b, 0xff, 0x2e, 0x37, 0xe4}
};

class WindowsError: public std::runtime_error {
public:
	WindowsError(): runtime_error("WindowsError") {}
};

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

template <class F, class ...A> void callWin(const char* msg, F&& f, A&& ...args)
{
	if (NTSTATUS status = f(std::forward<A>(args)...); status != CMC_STATUS_SUCCESS) {
		errorMessage(msg, status);
		throw WindowsError();
	}
}

int fwpmError(const char* msg, DWORD result)
{
	std::cerr << "WFP ERROR " << result << "msg" << '\n';
	return EXIT_FAILURE;
}

template <class F, class ...A> void callFwpm(const char* msg, F&& f, A&& ...args)
{
	if (DWORD result = f(std::forward<A>(args)...); result != ERROR_SUCCESS) {
		fwpmError(msg, result);
		throw WindowsError();
	}
}

std::atomic<bool> terminateFlag{false};
std::atomic<bool>terminateConfirm{false};

struct Stats {
	std::atomic<unsigned long long> packets{0};
	std::atomic<unsigned long long> bytes{0};
};
Stats stats{};

HANDLE fh = INVALID_HANDLE_VALUE;

BOOL terminateHandler([[maybe_unused]] DWORD ctrlType)
{
	terminateFlag = true;
	while (!terminateConfirm)
		CancelIoEx(fh, nullptr);
	std::cout << "User stats:\n" <<
		"packets=" << stats.packets.load() << '\n' <<
		"bytes=" << stats.bytes.load() << std::endl;
	PacketDriverStats driverStats;
	if (DWORD ret;
		!DeviceIoControl(fh, IOCTL_PACKETDRIVER_GET_STATS, nullptr, 0, &driverStats, sizeof(driverStats), &ret, nullptr))
	{
		errorMessage("IOCTL_ZERODRIVER_GET_STATS failed", GetLastError());
	} else {
		std::cout << "Kernel stats:\n" <<
			"receivedPackets=" << driverStats.receivedPackets << '\n' <<
			"receivedBytes=" << driverStats.receivedBytes << '\n' <<
			"receivedDroppedPackets=" << driverStats.receivedDroppedPackets << '\n' <<
			"sentPackets=" << driverStats.sentPackets << '\n' <<
			"sentBytes=" << driverStats.sentBytes << '\n' <<
			"sentFailedPackets=" << driverStats.sentFailedPackets << '\n' <<
			"sentDroppedPackets=" << driverStats.sentDroppedPackets << '\n' <<
			std::endl;
	}
	return FALSE;
}

int main()
try {
	// Parameters
	size_t bufferSize = 10 * (sizeof(PacketInfo) + 1500) + sizeof(PacketInfo); // space for 10 packets
    // Open device
    fh = CreateFile(PACKETDRIVER_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (fh == INVALID_HANDLE_VALUE)
		return errorMessage("Cannot open device", GetLastError());
	if (DWORD ret; !DeviceIoControl(fh, IOCTL_PACKETDRIVER_RESET_STATS, nullptr, 0, nullptr, 0, &ret, nullptr))
		return errorMessage("IOCTL_PACKETDRIVER_RESET_STATS failed", GetLastError());
	if (!SetConsoleCtrlHandler(terminateHandler, true))
		return errorMessage("SetConsoleCtrlHandler failed", GetLastError());
	// Configure packet filtering
	FWPM_SESSION0 session{};
	session.displayData.name = const_cast<wchar_t*>(L"PacketDriverTest session");
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	session.txnWaitTimeoutInMSec = INFINITE;
	HANDLE engine = nullptr;
	callFwpm("FwpmEngineOpen0 failed", FwpmEngineOpen0, nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &engine);
	FWPM_PROVIDER0 provider{};
	provider.providerKey = providerKeyGuid;
	provider.displayData.name = const_cast<wchar_t*>(L"PacketDriverTest provider");
	callFwpm("FwpmProviderAdd0 failed", FwpmProviderAdd0, engine, &provider, nullptr);
	FWPM_SUBLAYER0 sublayer{};
	sublayer.subLayerKey = sublayerKeyGuid;
	sublayer.displayData.name = const_cast<wchar_t*>(L"PacketDriverTest sublayer");
	sublayer.providerKey = const_cast<GUID*>(&providerKeyGuid);
	sublayer.weight = 0x8000;
	callFwpm("FwpmSublayerAdd0 failed", FwpmSubLayerAdd0, engine, &sublayer, nullptr);
	FWPM_FILTER0 filter{};
	filter.displayData.name = const_cast<wchar_t*>(L"PacketDriverTest filter");
	filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
	filter.providerKey = const_cast<GUID*>(&providerKeyGuid);
	filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
	filter.subLayerKey = sublayerKeyGuid;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 0;
	filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
	filter.action.calloutKey = PacketDriverCalloutGuid;
	callFwpm("FwpmFilterAdd0 inbound failed", FwpmFilterAdd0, engine, &filter, nullptr, nullptr);
	filter.layerKey = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
	callFwpm("FwpmFilterAdd0 outbound failed", FwpmFilterAdd0, engine, &filter, nullptr, nullptr);
	// Process packets
	std::vector<char> buffer(bufferSize);
	while (!terminateFlag) {
		DWORD rd;
		if (!ReadFile(fh, buffer.data(), DWORD(buffer.size()), &rd, nullptr)) {
			if (DWORD error = GetLastError(); error != ERROR_OPERATION_ABORTED)
				errorMessage("ReadFile failed", error);
			break;
		}
		terminateConfirm = true;
		size_t packets = 0;
		size_t bytes = 0;
		for (PacketInfo* p = reinterpret_cast<PacketInfo*>(buffer.data()); p->size > 0; ++p) {
			++packets;
			bytes += p->size;
		}
		stats.packets += packets;
		stats.bytes += bytes;
		terminateConfirm = false;
		if (terminateFlag)
			break;
		if (!WriteFile(fh, buffer.data(), rd, nullptr, nullptr)) {
			if (DWORD error = GetLastError(); error != ERROR_OPERATION_ABORTED)
				errorMessage("WriteFile failed", error);
			break;
		}
	}
	terminateConfirm = true;
	// Finish
    return EXIT_SUCCESS;
} catch (const WindowsError& e) {
	std::cerr << e.what() << "caught, exiting" << '\n';
	return EXIT_FAILURE;
}