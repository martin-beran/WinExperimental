#define NOMINMAX

#include "PacketDriver/PacketDriver.h"
#include "PCapFile/PcapFile.h"

#include <fwpmu.h>

#include <atomic>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>

// Operation mode
enum class Mode {
	Watch, // passive, only reading copies of packets
	Filter, // active, can pass, block, or modify packets
};

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
	std::wcerr << "ERROR 0x" << std::hex << err << std::dec << ": " << msg;
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
	std::cerr << "WFP ERROR 0x" << std::hex << result << std::dec << ": " << msg << '\n';
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
	std::atomic<unsigned long long> reads{0};
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
	return TRUE;
}

void printStats()
{
	std::cout << "User stats:\n" <<
		"reads=" << stats.reads.load() << '\n' <<
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
			"ignoredFragments=" << driverStats.ignoredFragments << '\n' <<
			"sentPackets=" << driverStats.sentPackets << '\n' <<
			"sentBytes=" << driverStats.sentBytes << '\n' <<
			"sentFailedPackets=" << driverStats.sentFailedPackets << '\n' <<
			"sentDroppedPackets=" << driverStats.sentDroppedPackets << '\n' <<
			std::endl;
	}
}

int usage()
{
	std::cerr << R"(usage: PacketDriverTest {watch|quietwatch|filter|quietfilter} [file.pcap]

watch ... get copy of packets, log each packet
quietwatch ... get copy of packets, do not log packets
filter ... intercept packets, log each packet
quietfilter ... intercept packets, do not log packets

file.pcap = optional output PCAP file where all captured packets will be saved
)";
	return EXIT_FAILURE;
}

int wmain(int argc, wchar_t* argv[], [[maybe_unused]] wchar_t* envp[])
{
	std::wstring pcapFileName;
	try {
		Mode mode = Mode::Watch;
		bool quiet = false;
		if (argc > 1) {
			using namespace std::string_literals;
			if (argv[1] == L"watch"s)
				mode = Mode::Watch;
			else if (argv[1] == L"quietwatch"s) {
				mode = Mode::Watch;
				quiet = true;
			} else if (argv[1] == L"filter"s)
				mode = Mode::Filter;
			else if (argv[1] == L"quietfilter"s) {
				mode = Mode::Filter;
				quiet = true;
			} else
				return usage();
		} else
			return usage();
		PCapFile pcap;
		if (argc > 2) {
			pcapFileName = argv[2];
			pcap = PCapFile(pcapFileName);
			pcap.create();
		}
		// Parameters
		size_t bufferSize = 10 * (sizeof(PacketInfo) + 1500) + sizeof(PacketInfo); // space for 10 packets
		// Open device
		fh = CreateFile(PACKETDRIVER_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
			nullptr);
		if (fh == INVALID_HANDLE_VALUE)
			return errorMessage("Cannot open device", GetLastError());
		if (DWORD ret; !DeviceIoControl(fh, mode == Mode::Watch ? IOCTL_PACKETDRIVER_WATCH : IOCTL_PACKETDRIVER_FILTER,
			nullptr, 0, nullptr, 0, &ret, nullptr))
		{
			return errorMessage("IOCTL_PACKETDRIVER_{WATCH|FILTER} failed", GetLastError());
		}
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
		FWPM_CALLOUT0 callout{};
		callout.calloutKey = PacketDriverInboundCalloutGuid;
		callout.displayData.name = const_cast<wchar_t*>(L"PacketDriverTest inbound callout");
		callout.providerKey = const_cast<GUID*>(&providerKeyGuid);
		callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4;
		callFwpm("FwpmCalloutAdd0 inbound failed", FwpmCalloutAdd0, engine, &callout, nullptr, nullptr);
		callout.calloutKey = PacketDriverOutboundCalloutGuid;
		callout.displayData.name = const_cast<wchar_t*>(L"PacketDriverTest outbound callout");
		callout.applicableLayer = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
		callFwpm("FwpmCalloutAdd0 outbound failed", FwpmCalloutAdd0, engine, &callout, nullptr, nullptr);
		FWPM_FILTER0 filter{};
		FWPM_FILTER_CONDITION0 filterCondition{};
		filter.displayData.name = const_cast<wchar_t*>(L"PacketDriverTest filter");
		filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
		filter.providerKey = const_cast<GUID*>(&providerKeyGuid);
		filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
		filter.subLayerKey = sublayerKeyGuid;
		filter.weight.type = FWP_EMPTY;
		filter.numFilterConditions = 1;
		filterCondition.fieldKey = FWPM_CONDITION_FLAGS; // ignore IP fragments
		filterCondition.matchType = FWP_MATCH_FLAGS_NONE_SET;
		filterCondition.conditionValue.type = FWP_UINT32;
		filterCondition.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_FRAGMENT;
		filter.filterCondition = &filterCondition;
		filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
		filter.action.calloutKey = PacketDriverInboundCalloutGuid;
		callFwpm("FwpmFilterAdd0 inbound failed", FwpmFilterAdd0, engine, &filter, nullptr, nullptr);
		filter.filterKey = {};
		filter.layerKey = FWPM_LAYER_OUTBOUND_IPPACKET_V4;
		filter.numFilterConditions = 0; // IP fragments can be only inbound
		filter.filterCondition = nullptr;
		filter.action.calloutKey = PacketDriverOutboundCalloutGuid;
		callFwpm("FwpmFilterAdd0 outbound failed", FwpmFilterAdd0, engine, &filter, nullptr, nullptr);
		// Process packets
		std::vector<char> buffer(bufferSize);
		size_t packetNo = 1;
		while (!terminateFlag) {
			DWORD rd;
			if (!ReadFile(fh, buffer.data(), DWORD(buffer.size()), &rd, nullptr)) {
				if (DWORD error = GetLastError(); error != ERROR_OPERATION_ABORTED)
					errorMessage("ReadFile failed", error);
				break;
			}
			++stats.reads;
			terminateConfirm = true;
			size_t packets = 0;
			size_t bytes = 0;
			for (PacketInfo* p = reinterpret_cast<PacketInfo*>(buffer.data()); p->size > 0; ++p) {
				++packets;
				bytes += p->size;
				if (!quiet)
					std::cout << packetNo++ << (p->direction == PacketInfo::Direction::Send ? " -> " : " <- ") << p->size <<
						std::endl;
			}
			std::cout << packets << " packets" << std::endl;
			if (pcap.isReady()) {
				char* pData = buffer.data() + (packets + 1) * sizeof(PacketInfo);
				for (PacketInfo* p = reinterpret_cast<PacketInfo*>(buffer.data()); p->size > 0; ++p) {
					pcap.writePacket(std::string_view(pData, p->size));
					pData += p->size;
				}
			}
			stats.packets += packets;
			stats.bytes += bytes;
			terminateConfirm = false;
			if (terminateFlag)
				break;
			if (mode == Mode::Filter)
				if (!WriteFile(fh, buffer.data(), rd, nullptr, nullptr)) {
					if (DWORD error = GetLastError(); error != ERROR_OPERATION_ABORTED)
						errorMessage("WriteFile failed", error);
					break;
				}
		}
		terminateConfirm = true;
		// Finish
		printStats();
		pcap.close();
		return EXIT_SUCCESS;
	} catch (const WindowsError& e) {
		std::cerr << e.what() << "caught, exiting" << '\n';
		printStats();
		return EXIT_FAILURE;
	} catch (const PCapFileError& e) {
		std::wcout << pcapFileName << ": " << e.what();
	}
}