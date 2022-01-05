#include "PacketDriver.h"

#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>

namespace {

	/*** IO queues *****************************************************************/

	WDFQUEUE ioctlQueue = WDF_NO_HANDLE;
	WDFQUEUE readQueue = WDF_NO_HANDLE;
	WDFQUEUE writeQueue = WDF_NO_HANDLE;

	struct QueueContextSpace {
		WDFQUEUE* queue;
	};
	WDF_DECLARE_CONTEXT_TYPE(QueueContextSpace);

	void QueueDestroyCallback(WDFOBJECT queue)
	{
		if (QueueContextSpace* space = WdfObjectGet_QueueContextSpace(queue); space && space->queue)
			*space->queue = WDF_NO_HANDLE;
	}

	class QueueLockGuard {
	public:
		QueueLockGuard(): QueueLockGuard(WDF_NO_HANDLE) {}
		QueueLockGuard(WDFQUEUE queue): queue(queue) {
			if (queue != WDF_NO_HANDLE)
				WdfObjectAcquireLock(queue);
		}
		QueueLockGuard(const QueueLockGuard&) = delete;
		QueueLockGuard(QueueLockGuard&& o) noexcept {
			queue = o.queue;
			o.queue = WDF_NO_HANDLE;
		}
		~QueueLockGuard() {
			unlock();
		}
		QueueLockGuard& operator=(const QueueLockGuard&) = delete;
		QueueLockGuard& operator=(QueueLockGuard&& o) noexcept {
			if (this != &o) {
				unlock();
				queue = o.queue;
				o.queue = WDF_NO_HANDLE;
			}
			return *this;
		}
	private:
		void unlock() {
			if (queue != WDF_NO_HANDLE)
				WdfObjectReleaseLock(queue);
		}
		WDFQUEUE queue;
	};

	/*** IOCTL *********************************************************************/

	// Access to all IOCTL variables require holding ioctlQueue lock

	PacketDriverStats stats{}; // statistics
	bool filterMode = false; // Watch (false) or filter (true)

	/*** Packet read processing ****************************************************/

	bool ioReadReady = false;

	class PacketStorage {
	public:
		bool empty() {
			return popPacketIdx == count[popSelect] && count[1 - popSelect] == 0;
		}
		NTSTATUS init() {
			if (storedPackets == 0) {
				DbgPrint("PacketStorage storedPackets=0");
				destroy();
				return STATUS_UNSUCCESSFUL;
			}
			if (storedBytes == 0) {
				DbgPrint("PacketStorage storedBytes=0");
				destroy();
				return STATUS_UNSUCCESSFUL;
			}
			for (PacketInfo*& p : info) {
				p = reinterpret_cast<PacketInfo*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*p) * storedPackets,
					PACKETDRIVER_TAG));
				if (!p) {
					DbgPrint("Cannot allocate PacketInfo array");
					destroy();
					return STATUS_INSUFFICIENT_RESOURCES;
				}
			}
			for (char*& p : data) {
				p = reinterpret_cast<char*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, storedBytes, PACKETDRIVER_TAG));
				if (!p) {
					DbgPrint("Cannot allocate packet data array");
					destroy();
					return STATUS_INSUFFICIENT_RESOURCES;
				}
			}
			return STATUS_SUCCESS;
		}
		void destroy() {
			for (PacketInfo*& p : info)
				if (p) {
					ExFreePool(p);
					p = nullptr;
				}
			for (char*& p : data) {
				if (p) {
					ExFreePool(p);
					p = nullptr;
				}
			}
		}
		void* insert(size_t sz, const FWPS_INCOMING_METADATA_VALUES0* meta, const UINT32* interfaceIdx,
			const UINT32* subinterfaceIdx, PacketInfo::Direction direction)
		{
			if (sz > storedBytes)
				return nullptr; // packet does not fit to the data buffer
			if ((meta->currentMetadataValues & neededMetadata) != neededMetadata)
				return nullptr; // not all required metadata are available
			if (direction == PacketInfo::Direction::Receive)
				if ((meta->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) !=
					FWPS_METADATA_FIELD_IP_HEADER_SIZE ||
					!interfaceIdx || !subinterfaceIdx)
				{
					return nullptr; // not all required metadata are available
				}
			if (count[pushSelect] >= storedPackets || pushDataIdx + sz >= storedBytes) {
				pushSelect = 1 - pushSelect;
				if (popSelect == pushSelect) {
					popSelect = 1 - popSelect;
					popPacketIdx = 0;
					popDataIdx = 0;
				}
				{
					QueueLockGuard lock(ioctlQueue);
					stats.receivedDroppedPackets += count[pushSelect];
				}
				count[pushSelect] = 0;
				pushDataIdx = 0;
			}
			PacketInfo& pi = info[pushSelect][count[pushSelect]];
			pi.direction = direction;
			pi.compartment = static_cast<COMPARTMENT_ID>(meta->compartmentId);
			pi.interfaceIdx = IF_INDEX(interfaceIdx ? *interfaceIdx : 0);
			pi.subinterfaceIdx = IF_INDEX(subinterfaceIdx ? *subinterfaceIdx : 0);
			pi.size = sz;
			void* result = data[pushSelect] + pushDataIdx;
			++count[pushSelect];
			pushDataIdx += sz;
			return result;
		}
		void* get(PacketInfo*& packetInfo) {
			if (count[popSelect] != 0 && popPacketIdx == count[popSelect]) {
				popSelect = 1 - popSelect;
				popPacketIdx = 0;
				popDataIdx = 0;
			}
			if (popPacketIdx < count[popSelect]) {
				packetInfo = &info[popSelect][popPacketIdx];
				return &data[popSelect][popDataIdx];
			} else {
				packetInfo = nullptr;
				return nullptr;
			}
		}
		void pop() {
			popDataIdx += info[popSelect][popPacketIdx++].size;
		}
		void save() {
			savedPopSelect = popSelect;
			savedPopPacketIdx = popPacketIdx;
			savedPopDataIdx = popDataIdx;
		}
		void restore() {
			popSelect = savedPopSelect;
			popPacketIdx = savedPopPacketIdx;
			popDataIdx = savedPopDataIdx;
		}
	private:
		static constexpr UINT32 neededMetadata = FWPS_METADATA_FIELD_COMPARTMENT_ID;
		size_t storedPackets = maxReadStoredPackets;
		size_t storedBytes = maxReadStoredBytes;
		PacketInfo* info[2] = {nullptr, nullptr};
		char* data[2] = {nullptr, nullptr};
		size_t count[2] = {0, 0};
		size_t pushSelect = 0;
		size_t pushDataIdx = 0;
		size_t popSelect = 0;
		size_t popPacketIdx = 0;
		size_t popDataIdx = 0;
		size_t savedPopSelect = 0;
		size_t savedPopPacketIdx = 0;
		size_t savedPopDataIdx = 0;
	};
	// Requires holding readQueue lock
	PacketStorage storage;

	// Must be called with locked synchronization lock of readQueue
	bool doPacketRead(bool readReady, NET_BUFFER_LIST* packet, const FWPS_INCOMING_METADATA_VALUES0* meta,
		const UINT32*interfaceIdx, const UINT32* subinterfaceIdx, PacketInfo::Direction direction)
	{
		if (readReady)
			ioReadReady = true;
		if (packet && meta) {
			if (NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(packet)) {
				ULONG dataLength = nb->DataLength;
				if (void* packetData = storage.insert(dataLength, meta, interfaceIdx, subinterfaceIdx, direction)) {
					if (void* p = NdisGetDataBuffer(nb, dataLength, packetData, 1, 0)) {
						if (p != packetData)
							RtlCopyMemory(packetData, p, dataLength);
					}
				}
			}
		}
		// Here, we have an IO read requests and a packet to be returned
		ULONGLONG receivedPackets = 0;
		ULONGLONG receivedBytes = 0;
		while (ioReadReady && !storage.empty()) {
			// Get the next I/O request
			WDFREQUEST request;
			if (NTSTATUS status = WdfIoQueueRetrieveNextRequest(readQueue, &request); status != STATUS_SUCCESS) {
				if (status == STATUS_NO_MORE_ENTRIES)
					ioReadReady = false;
				break;
			}
			// Compute how many packet fit into the request
			void* buffer;
			size_t bufsz;
			// always return at least one packet plus the terminating PacketInfo (with size == 0)
			if (WdfRequestRetrieveOutputBuffer(request, 2 * sizeof(PacketInfo), &buffer, &bufsz) != STATUS_SUCCESS) {
				WdfRequestCompleteWithInformation(request, STATUS_UNSUCCESSFUL, 0);
				continue;
			}
			size_t used = sizeof(PacketInfo); // terminating PacketInfo
			storage.save();
			PacketInfo* info = nullptr;
			size_t n = 0;
			// The first packet in a request may be partial, others must fit as whole, or they are postponed to next requests
			for (void* data;
				(data = storage.get(info)) != nullptr && used + sizeof(PacketInfo) + (n == 0 ? 0 : info->size) <= bufsz;)
			{
				++n;
				used += sizeof(PacketInfo);
				used += min(info->size, bufsz - used);
				storage.pop();
			}
			// Store packets into the request
			storage.restore();
			PacketInfo* bufPkt = reinterpret_cast<PacketInfo*>(buffer);
			used = (n + 1) * sizeof(PacketInfo);
			char* bufData = reinterpret_cast<char*>(buffer) + used;
			for (size_t i = 0; i < n; ++i) {
				void* data = storage.get(info);
				bufPkt[i] = *info;
				receivedBytes += bufPkt->size;
				if (bufPkt->size > bufsz - used)
					bufPkt[i].size = bufsz - used;
				RtlCopyMemory(bufData, data, bufPkt[i].size);
				used += bufPkt[i].size;
				storage.pop();
			}
			// buffer overflow reported, but buffer has space for at least n + 1 PacketInfo structures
#pragma warning(suppress: 6386)
			bufPkt[n] = {};
			receivedPackets += n;
			WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, used);
		}
		QueueLockGuard lock(ioctlQueue);
		if (receivedPackets != 0 || receivedBytes != 0) {
			stats.receivedPackets += receivedPackets;
			stats.receivedBytes += receivedBytes;
		}
		return filterMode;
	}

	/*** Packet write processing ***************************************************/

	// Require holding ioctlQueue lock
	// This requirement is a bit weird, but we need ioctlQueue lock nearby anyway in order to modify stats.
	// We cannot use writeQueue lock, because injectComplete() can be called synchronously by FwpsInjectNetworkSendAsync0()
	// or FwpsInjectNetworkReceiveAsync0(), called from doPacketWrite() while already holding the writeQueue lock.
	// A double-lock triggers a bug-check (BSOD).
	ULONGLONG writingPackets = 0;
	ULONGLONG writingBytes = 0;
	
	NDIS_HANDLE pool;

	HANDLE injectionHandleIpv4;
	HANDLE injectionHandleIpv6;

	void injectComplete([[maybe_unused]] void* context, NET_BUFFER_LIST* nbl, [[maybe_unused]] BOOLEAN dispatchLevel)

	{
		ULONG dataLength = NET_BUFFER_LIST_FIRST_NB(nbl)->DataLength;
		{
			QueueLockGuard lock(ioctlQueue);
			++stats.sentPackets;
			stats.sentBytes += dataLength;
			// Do not block sending more packets if there is a bug causing a bad value of writingPackets or writingBytes
			if (writingPackets > 0)
				--writingPackets;
			if (writingBytes >= dataLength)
				writingBytes -= dataLength;
			else
				writingBytes = 0;
		}
		FwpsFreeNetBufferList0(nbl);
	}

	// Called with holding writeQueue lock
	void doPacketWrite(PacketInfo& info, char* data)
	{
		{
			QueueLockGuard lock(ioctlQueue);
			if (!filterMode)
				return; // no writing in watch mode
			if (writingPackets >= maxWriteStoredPackets || writingBytes + info.size > maxWriteStoredBytes) {
				++stats.sentDroppedPackets;
				return;
			}
			++writingPackets;
			writingBytes += info.size;
		}
		void* buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, info.size, PACKETDRIVER_TAG);
		MDL* mdl = nullptr;
		NET_BUFFER_LIST* bufferList = nullptr;
		if (!buffer)
			goto fail;
		RtlCopyMemory(buffer, data, info.size);
		mdl = IoAllocateMdl(buffer, static_cast<ULONG>(info.size), false, false, nullptr);
		if (!mdl)
			goto fail;
		MmBuildMdlForNonPagedPool(mdl);
		if (FwpsAllocateNetBufferAndNetBufferList0(pool, 0, 0, mdl, 0, info.size, &bufferList) != STATUS_SUCCESS)
			goto fail;
		mdl = nullptr;
		buffer = nullptr;
		// TODO injection of IPv6 via injectionHandleIpv6
		switch (info.direction) {
		case PacketInfo::Direction::Send:
			if (FwpsInjectNetworkSendAsync0(injectionHandleIpv4, nullptr, 0, info.compartment, bufferList,
				injectComplete, nullptr) != STATUS_SUCCESS)
			{
				goto fail;
			}
			break;
		case PacketInfo::Direction::Receive:
			if (FwpsInjectNetworkReceiveAsync0(injectionHandleIpv4, nullptr, 0, info.compartment, info.interfaceIdx,
				info.subinterfaceIdx, bufferList, injectComplete, nullptr) != STATUS_SUCCESS)
			{
				goto fail;
			}
			break;
		default:
			goto fail;
		}
		return;
	fail:
		{
			QueueLockGuard lock(ioctlQueue);
			--writingPackets;
			writingBytes -= info.size;
		}
		if (bufferList)
			FwpsFreeNetBufferList0(bufferList);
		if (mdl)
			IoFreeMdl(mdl);
		if (buffer)
			ExFreePool(buffer);
		QueueLockGuard lock(ioctlQueue);
		++stats.sentFailedPackets;
	}

	/*** WFP callout handler *******************************************************/

	struct DeviceContextSpace {
		bool inboundCalloutRegistered;
		UINT32 inboundCalloutId;
		bool outboundCalloutRegistered;
		UINT32 outboundCalloutId;
		HANDLE* injectionHandleIpv4;
		HANDLE* injectionHandleIpv6;
		NDIS_HANDLE pool = nullptr;
	};
	WDF_DECLARE_CONTEXT_TYPE(DeviceContextSpace);

	void DeviceDestroyCallback(WDFOBJECT device)
	{
		DbgPrint("DeviceDestroyCallback");
		if (DeviceContextSpace* space = WdfObjectGet_DeviceContextSpace(device); space) {
			if (space->inboundCalloutRegistered) {
				if (NTSTATUS status = FwpsCalloutUnregisterById0(space->inboundCalloutId); status != STATUS_SUCCESS)
					DbgPrint("FwpsCalloutUnregisterById0 inbound status=%#lx", status);
				space->inboundCalloutRegistered = false;
			}
			if (space->outboundCalloutRegistered) {
				if (NTSTATUS status = FwpsCalloutUnregisterById0(space->outboundCalloutId); status != STATUS_SUCCESS)
					DbgPrint("FwpsCalloutUnregisterById0 outbound status=%#lx", status);
				space->outboundCalloutRegistered = false;
			}
			if (space->injectionHandleIpv4) {
				if (NTSTATUS status = FwpsInjectionHandleDestroy0(*space->injectionHandleIpv4); status != STATUS_SUCCESS)
					DbgPrint("FwpsInjectionHandleDestroy0(IPv4) status=%#lx", status);
				space->injectionHandleIpv4 = nullptr;
			}
			if (space->injectionHandleIpv6) {
				if (NTSTATUS status = FwpsInjectionHandleDestroy0(*space->injectionHandleIpv6); status != STATUS_SUCCESS)
					DbgPrint("FwpsInjectionHandleDestroy0(IPv6) status=%#lx", status);
				space->injectionHandleIpv6 = nullptr;
			}
			if (space->pool)
				NdisFreeNetBufferListPool(space->pool);
		}
		storage.destroy();
	}

	const UINT32* getIncomingValue(const FWPS_INCOMING_VALUES0* inFixedValues, FWPS_FIELDS_INBOUND_IPPACKET_V4 field)
	{
		switch (inFixedValues->layerId) {
		case FWPS_LAYER_INBOUND_IPPACKET_V4:
			if (inFixedValues->valueCount <= size_t(field))
				return nullptr;
			{
				FWP_VALUE0& val = inFixedValues->incomingValue[field].value;
				if (val.type != FWP_UINT32)
					return nullptr;
				return &val.uint32;
			}
			break;
		case FWPS_LAYER_INBOUND_IPPACKET_V6:
			// TODO
			return nullptr;
		default:
			return nullptr;
		}
	}

	const UINT32* getInterfaceIdx(const FWPS_INCOMING_VALUES0* inFixedValues)
	{
		return getIncomingValue(inFixedValues, FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX);
	}

	const UINT32* getSubinterfaceIdx(const FWPS_INCOMING_VALUES0* inFixedValues)
	{
		return getIncomingValue(inFixedValues, FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX);
	}

	void packetClassifyFn(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
		void* layerData, [[maybe_unused]] const FWPS_FILTER0* filter, [[maybe_unused]] UINT64 flowContext,
		FWPS_CLASSIFY_OUT0* classifyOut, PacketInfo::Direction direction)
	{
		if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) // Cannot modify verdict
			return;
		if (!layerData) {
			// No packet data
			classifyOut->actionType = FWP_ACTION_CONTINUE;
			return;
		}
		NET_BUFFER_LIST* nbl = reinterpret_cast<NET_BUFFER_LIST*>(layerData);
		FWPS_PACKET_INJECTION_STATE injectionState = FWPS_PACKET_NOT_INJECTED;
		switch (inFixedValues->layerId) {
		case FWPS_LAYER_INBOUND_IPPACKET_V4:
		case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
			injectionState = FwpsQueryPacketInjectionState0(injectionHandleIpv4, nbl, nullptr);
			break;
		case FWPS_LAYER_INBOUND_IPPACKET_V6:
		case FWPS_LAYER_OUTBOUND_IPPACKET_V6:
			injectionState = FwpsQueryPacketInjectionState0(injectionHandleIpv6, nbl, nullptr);
			break;
		default:
			// Unsupported layer
			classifyOut->actionType = FWP_ACTION_CONTINUE;
			return;
		}
		if (injectionState == FWPS_PACKET_INJECTED_BY_SELF || injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
			// Break a cycle for an injected packet
			classifyOut->actionType = FWP_ACTION_CONTINUE;
			return;
		}
		if (direction == PacketInfo::Direction::Receive) {
			if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) !=
				FWPS_METADATA_FIELD_IP_HEADER_SIZE)
			{
				return;
			}
			NdisRetreatNetBufferListDataStart(nbl, inMetaValues->ipHeaderSize, 0, nullptr, nullptr);
		}
		QueueLockGuard lock(readQueue);
		bool block = doPacketRead(false, nbl, inMetaValues, getInterfaceIdx(inFixedValues), getSubinterfaceIdx(inFixedValues),
			direction);
		if (direction == PacketInfo::Direction::Receive)
			NdisAdvanceNetBufferListDataStart(nbl, inMetaValues->ipHeaderSize, false, nullptr);
		if (block) {
			// Consume the packet silently
			classifyOut->actionType = FWP_ACTION_BLOCK;
			classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		} else
			classifyOut->actionType = FWP_ACTION_PERMIT;
	}

	void packetClassifyFnInbound(const FWPS_INCOMING_VALUES0* inFixedValues,
		const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, const FWPS_FILTER0* filter, UINT64 flowContext,
		FWPS_CLASSIFY_OUT0* classifyOut)
	{
		packetClassifyFn(inFixedValues, inMetaValues, layerData, filter, flowContext, classifyOut,
			PacketInfo::Direction::Receive);
	}

	void packetClassifyFnOutbound(const FWPS_INCOMING_VALUES0* inFixedValues,
		const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, void* layerData, const FWPS_FILTER0* filter, UINT64 flowContext,
		FWPS_CLASSIFY_OUT0* classifyOut)
	{
		packetClassifyFn(inFixedValues, inMetaValues, layerData, filter, flowContext, classifyOut,
			PacketInfo::Direction::Send);
	}

	NTSTATUS packetNotifyFn([[maybe_unused]] FWPS_CALLOUT_NOTIFY_TYPE notifyType, [[maybe_unused]] const GUID* filterKey,
		[[maybe_unused]] FWPS_FILTER0* filter)
	{
		return STATUS_SUCCESS;
	}

	/*** Device IO callbacks *******************************************************/

	void EvtIoDeviceControl([[maybe_unused]] WDFQUEUE Queue, WDFREQUEST Request, [[maybe_unused]] size_t OutputBufferLength,
		[[maybe_unused]] size_t InputBufferLength, ULONG IoControlCode)
	{
		ULONG_PTR transferred = 0;
		switch (IoControlCode) {
		case IOCTL_PACKETDRIVER_GET_STATS:
		case IOCTL_PACKETDRIVER_GET_AND_RESET_STATS:
		{
			WDFMEMORY memory;
			if (NTSTATUS status = WdfRequestRetrieveOutputMemory(Request, &memory); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_PACKETDRIVER_GET_STATS WdfRequestRetrieveInputMemory status=%#lx", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			if (NTSTATUS status = WdfMemoryCopyFromBuffer(memory, 0, &stats, sizeof(stats)); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_PACKETDRIVER_GET_STATS WdfMemoryCopyFromBuffer status=%#lx", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			transferred = sizeof(stats);
			if (IoControlCode == IOCTL_PACKETDRIVER_GET_STATS)
				break;
			[[fallthrough]];
		}
		case IOCTL_PACKETDRIVER_RESET_STATS:
			stats = {};
			break;
		case IOCTL_PACKETDRIVER_WATCH:
			filterMode = false;
			break;
		case IOCTL_PACKETDRIVER_FILTER:
			filterMode = true;
			break;
		default:
			WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
			break;
		}
		WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, transferred);
	}

	void EvtIoReadReady([[maybe_unused]] WDFQUEUE Queue, [[maybe_unused]] WDFCONTEXT Context)
	{
		doPacketRead(true, nullptr, nullptr, nullptr, nullptr, PacketInfo::Direction::Receive);
	}

	void requestComplete(WDFREQUEST request, const char* msg, NTSTATUS status)
	{
		if (status != STATUS_SUCCESS)
			DbgPrint("%s status=%#lx", msg, status);
		WdfRequestCompleteWithInformation(request, status, 0);
	}

	void EvtIoWrite([[maybe_unused]] WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
	{
		// Get input buffer
		if (Length < sizeof(PacketInfo)) {
			requestComplete(Request, "EvtIoWrite: Smaller than PacketInfo", STATUS_BUFFER_TOO_SMALL);
			return;
		}
		void* ioBuf;
		if (NTSTATUS status = WdfRequestRetrieveInputBuffer(Request, Length, &ioBuf, nullptr)) {
			requestComplete(Request, "WdfRequestRetrieveInputBuffer", status);
			return;
		}
		// Check buffer content
		PacketInfo* pInfo = reinterpret_cast<PacketInfo*>(ioBuf);
		size_t n = 0;
		size_t dataSize = 0;
		while (Length - n * sizeof(PacketInfo) >= sizeof(PacketInfo) && pInfo[n].size > 0) {
			dataSize += pInfo[n].size;
			++n;
		}
		if (Length - n * sizeof(PacketInfo) < sizeof(PacketInfo)) {
			requestComplete(Request, "EvtIoWrite: Truncated PacketInfo", STATUS_BUFFER_TOO_SMALL);
			return;
		}
		char* pData = reinterpret_cast<char*>(pInfo + n + 1);
		if (Length - (n + 1) * sizeof(PacketInfo) < dataSize) {
			requestComplete(Request, "EvtIoWrite: Truncated packet data", STATUS_BUFFER_TOO_SMALL);
			return;
		}
		// Now pInfo[0...n-1] and pData[0...dataSize-1] are valid
		for (size_t i = 0; i < n; ++i) {
			doPacketWrite(pInfo[i], pData);
			pData += pInfo[i].size;
		}
		requestComplete(Request, "OK", STATUS_SUCCESS);
	}

	/*** IO device initialization **************************************************/

	NTSTATUS EvtDeviceAdd([[maybe_unused]] WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
	{
		// Create device
		DECLARE_CONST_UNICODE_STRING(deviceName, PACKETDRIVER_DEVICE);
		if (NTSTATUS status = WdfDeviceInitAssignName(DeviceInit, &deviceName); status != STATUS_SUCCESS) {
			DbgPrint("WdfDeviceInitAssignName status=%#lx", status);
			return status;
		}
		WDF_OBJECT_ATTRIBUTES qAttr;
		WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&qAttr, DeviceContextSpace);
		qAttr.EvtDestroyCallback = DeviceDestroyCallback;
		WDF_IO_TYPE_CONFIG ioConfig;
		WDF_IO_TYPE_CONFIG_INIT(&ioConfig);
		ioConfig.ReadWriteIoType = WdfDeviceIoDirect;
		WdfDeviceInitSetIoTypeEx(DeviceInit, &ioConfig);
		WDFDEVICE hDevice;
		if (NTSTATUS status = WdfDeviceCreate(&DeviceInit, &qAttr, &hDevice); status != STATUS_SUCCESS) {
			DbgPrint("EvtDeviceAdd status=%#lx\n", status);
			return status;
		}
		// Initialize packet storage
		if (NTSTATUS status = storage.init(); status != STATUS_SUCCESS)
			return status;
		// Create IO queues
		WDF_IO_QUEUE_CONFIG qConfig;
		WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&qAttr, QueueContextSpace);
		qAttr.SynchronizationScope = WdfSynchronizationScopeQueue;
		qAttr.EvtDestroyCallback = QueueDestroyCallback;
		// Create default IO queue, used for IOCTL requests
		WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qConfig, WdfIoQueueDispatchSequential);
		qConfig.EvtIoDeviceControl = EvtIoDeviceControl;
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &ioctlQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%#lx", status);
			return status;
		}
		WdfObjectGet_QueueContextSpace(ioctlQueue)->queue = &ioctlQueue;
		// Create IO queue for reading packets
		WDF_IO_QUEUE_CONFIG_INIT(&qConfig, WdfIoQueueDispatchManual);
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &readQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%#lx", status);
			return status;
		}
		WdfObjectGet_QueueContextSpace(readQueue)->queue = &readQueue;
		// The third parameter is unused by EvtIoReadReady, but documentation does not say clearly if it can be NULL
		if (NTSTATUS status = WdfIoQueueReadyNotify(readQueue, EvtIoReadReady, &readQueue); status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueReadyNotify(read) status=%#lx", status);
			return status;
		}
		if (NTSTATUS status = WdfDeviceConfigureRequestDispatching(hDevice, readQueue, WdfRequestTypeRead);
			status != STATUS_SUCCESS)
		{
			DbgPrint("WdfDeviceConfigureRequestDispatching(read) status=%#lx", status);
			return status;
		}
		// Create IO queue for writing packets
		WDF_IO_QUEUE_CONFIG_INIT(&qConfig, WdfIoQueueDispatchSequential);
		qConfig.EvtIoWrite = EvtIoWrite;
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &writeQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%#lx", status);
			return status;
		}
		WdfObjectGet_QueueContextSpace(writeQueue)->queue = &writeQueue;
		if (NTSTATUS status = WdfDeviceConfigureRequestDispatching(hDevice, writeQueue, WdfRequestTypeWrite);
			status != STATUS_SUCCESS)
		{
			DbgPrint("WdfDeviceConfigureRequestDispatching(write) status=%#lx", status);
			return status;
		}
		// Initialize WFP callout
		PDEVICE_OBJECT deviceObject = WdfDeviceWdmGetDeviceObject(hDevice);
		FWPS_CALLOUT0 callout{
			PacketDriverInboundCalloutGuid,
			0,
			packetClassifyFnInbound,
			packetNotifyFn,
			nullptr
		};
		DeviceContextSpace* deviceContext = WdfObjectGet_DeviceContextSpace(hDevice);
		NTSTATUS status = STATUS_SUCCESS;
		if (status == STATUS_SUCCESS &&
			(status = FwpsCalloutRegister0(deviceObject, &callout, &deviceContext->inboundCalloutId)) != STATUS_SUCCESS)
		{
			DbgPrint("FwpsCalloutRegister0 inbound status=%#lx", status);
		} else
			deviceContext->inboundCalloutRegistered = true;
		callout.calloutKey = PacketDriverOutboundCalloutGuid;
		callout.classifyFn = packetClassifyFnOutbound;
		if (status == STATUS_SUCCESS &&
			(status = FwpsCalloutRegister0(deviceObject, &callout, &deviceContext->outboundCalloutId)) != STATUS_SUCCESS)
		{
			DbgPrint("FwpsCalloutRegister0 outbound status=%#lx", status);
		} else
			deviceContext->outboundCalloutRegistered = true;
		if (status == STATUS_SUCCESS &&
			(status = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &injectionHandleIpv4))
			!= STATUS_SUCCESS)
		{
			DbgPrint("FwpsInjectionHandleCreate0(IPv4) status=%#lx", status);
		} else
			deviceContext->injectionHandleIpv4 = &injectionHandleIpv4;
		if (status == STATUS_SUCCESS &&
			(status = FwpsInjectionHandleCreate0(AF_INET6, FWPS_INJECTION_TYPE_NETWORK, &injectionHandleIpv6))
			!= STATUS_SUCCESS)
		{
			DbgPrint("FwpsInjectionHandleCreate0(IPv6) status=%#lx", status);
		} else
			deviceContext->injectionHandleIpv6 = &injectionHandleIpv6;
		NET_BUFFER_LIST_POOL_PARAMETERS poolParams;
		poolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		poolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		poolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		poolParams.ProtocolId = 0;
		poolParams.fAllocateNetBuffer = true;
		poolParams.ContextSize = 0;
		poolParams.PoolTag = PACKETDRIVER_TAG;
		poolParams.DataSize = 0;
		if (status == STATUS_SUCCESS && (pool = NdisAllocateNetBufferListPool(nullptr, &poolParams)) == nullptr) {
			DbgPrint("NdisAllocateNetBufferListPool failed");
			status = STATUS_UNSUCCESSFUL;
		}
		deviceContext->pool = pool;
		if (status != STATUS_SUCCESS)
			DeviceDestroyCallback(hDevice);
		return status;
	}
}

/*** Driver initialization *********************************************************/

extern "C" {
	DRIVER_INITIALIZE DriverEntry;

	NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
	{
		WDF_DRIVER_CONFIG config;
		WDF_DRIVER_CONFIG_INIT(&config, EvtDeviceAdd);
		NTSTATUS status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
		DbgPrint("DriverEntry status=%#lx\n", status);
		return status;
	}
}