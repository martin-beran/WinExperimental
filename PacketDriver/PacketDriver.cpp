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
		QueueLockGuard(WDFQUEUE queue) : queue(queue) {
			if (queue != WDF_NO_HANDLE)
				WdfObjectAcquireLock(queue);
		}
		QueueLockGuard(const QueueLockGuard&) = delete;
		QueueLockGuard(QueueLockGuard&&) = delete;
		~QueueLockGuard() {
			if (queue != WDF_NO_HANDLE)
				WdfObjectReleaseLock(queue);
		}
		QueueLockGuard& operator=(const QueueLockGuard&) = delete;
		QueueLockGuard& operator=(QueueLockGuard&&) = delete;
	private:
		WDFQUEUE queue;
	};

	/*** Statistics ****************************************************************/

	PacketDriverStats stats{};

	/*** Packet read processing ****************************************************/

	bool ioReadReady = false;
	bool wfpPacketReady = false;

	// Must be called with locked synchronization lock of readQueue
	void doPacketRead(bool readReady, bool packetReady)
	{
		if (readReady)
			ioReadReady = true;
		if (packetReady)
			wfpPacketReady = true;
		if (!ioReadReady || !wfpPacketReady)
			return;
		// Here, we have an IO read requests and a packet to be returned
	}

	/*** WFP callout handler *******************************************************/

	HANDLE injectionHandleIpv4;
	HANDLE injectionHandleIpv6;

	struct DeviceContextSpace {
		bool calloutRegistered;
		UINT32 calloutId;
		HANDLE* injectionHandleIpv4;
		HANDLE* injectionHandleIpv6;
	};
	WDF_DECLARE_CONTEXT_TYPE(DeviceContextSpace);

	void DeviceDestroyCallback(WDFOBJECT device)
	{
		if (DeviceContextSpace* space = WdfObjectGet_DeviceContextSpace(device); space) {
			if (space->calloutRegistered) {
				if (NTSTATUS status = FwpsCalloutUnregisterById0(space->calloutId); status != STATUS_SUCCESS)
					DbgPrint("FwpsCalloutUnregisterById0 status=%ld", status);
				space->calloutRegistered = false;
			}
			if (space->injectionHandleIpv4) {
				if (NTSTATUS status = FwpsInjectionHandleDestroy0(*space->injectionHandleIpv4); status != STATUS_SUCCESS)
					DbgPrint("FwpsInjectionHandleDestroy0(IPv4) status=%ld", status);
				space->injectionHandleIpv4 = nullptr;
			}
			if (space->injectionHandleIpv6) {
				if (NTSTATUS status = FwpsInjectionHandleDestroy0(*space->injectionHandleIpv6); status != STATUS_SUCCESS)
					DbgPrint("FwpsInjectionHandleDestroy0(IPv6) status=%ld", status);
				space->injectionHandleIpv6 = nullptr;
			}
		}
	}

	void packetClassifyFn(const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* /*inMetaValues*/,
		void* layerData, [[maybe_unused]] const FWPS_FILTER0* filter, [[maybe_unused]] UINT64 flowContext,
		FWPS_CLASSIFY_OUT0* classifyOut)
	{
		if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) // Cannot modify verdict
			return;
		if (!layerData) {
			// No packet data
			classifyOut->actionType = FWP_ACTION_CONTINUE;
			return;
		}
		FWPS_PACKET_INJECTION_STATE injectionState = FWPS_PACKET_NOT_INJECTED;
		switch (inFixedValues->layerId) {
		case FWPS_LAYER_INBOUND_IPPACKET_V4:
		case FWPS_LAYER_INBOUND_TRANSPORT_V4:
		case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
		case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
			injectionState = FwpsQueryPacketInjectionState0(injectionHandleIpv4,
				reinterpret_cast<const NET_BUFFER_LIST*>(layerData), nullptr);
			break;
		case FWPS_LAYER_INBOUND_IPPACKET_V6:
		case FWPS_LAYER_INBOUND_TRANSPORT_V6:
		case FWPS_LAYER_OUTBOUND_IPPACKET_V6:
		case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
			injectionState = FwpsQueryPacketInjectionState0(injectionHandleIpv6,
				reinterpret_cast<const NET_BUFFER_LIST*>(layerData), nullptr);
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
		// TODO
		// Consume the packet silently
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
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
				DbgPrint("IOCTL_PACKETDRIVER_GET_STATS WdfRequestRetrieveInputMemory status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			if (NTSTATUS status = WdfMemoryCopyFromBuffer(memory, 0, &stats, sizeof(stats)); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_PACKETDRIVER_GET_STATS WdfMemoryCopyFromBuffer status=%ld", status);
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
		break; default:
			WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
			break;
		}
	}

	void EvtIoReadReady([[maybe_unused]] WDFQUEUE Queue, [[maybe_unused]] WDFCONTEXT Context)
	{	
		doPacketRead(true, false);
	}

	void EvtIoWrite([[maybe_unused]] WDFQUEUE Queue, WDFREQUEST /*Request*/, size_t /*Length*/)
	{
		// TODO
	}

	/*** IO device initialization **************************************************/

	NTSTATUS EvtDeviceAdd([[maybe_unused]] WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
	{
		// Create device
		DECLARE_CONST_UNICODE_STRING(deviceName, PACKETDRIVER_DEVICE);
		if (NTSTATUS status = WdfDeviceInitAssignName(DeviceInit, &deviceName); status != STATUS_SUCCESS) {
			DbgPrint("WdfDeviceInitAssignName status=%ld", status);
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
			DbgPrint("EvtDeviceAdd status=%ld\n", status);
			return status;
		}
		// Create IO queues
		WDF_IO_QUEUE_CONFIG qConfig;
		WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&qAttr, QueueContextSpace);
		qAttr.SynchronizationScope = WdfSynchronizationScopeQueue;
		qAttr.EvtDestroyCallback = QueueDestroyCallback;
		// Create default IO queue, used for IOCTL requests
		WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qConfig, WdfIoQueueDispatchSequential);
		qConfig.EvtIoDeviceControl = EvtIoDeviceControl;
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &ioctlQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%ld", status);
			return status;
		}
		WdfObjectGet_QueueContextSpace(ioctlQueue)->queue = &ioctlQueue;
		// Create IO queue for reading packets
		WDF_IO_QUEUE_CONFIG_INIT(&qConfig, WdfIoQueueDispatchManual);
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &readQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%ld", status);
			return status;
		}
		WdfObjectGet_QueueContextSpace(readQueue)->queue = &readQueue;
		if (NTSTATUS status = WdfIoQueueReadyNotify(readQueue, EvtIoReadReady, nullptr); status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueReadyNotify(read) status=%ld", status);
			return status;
		}
		if (NTSTATUS status = WdfDeviceConfigureRequestDispatching(hDevice, readQueue, WdfRequestTypeRead);
			status != STATUS_SUCCESS)
		{
			DbgPrint("WdfDeviceConfigureRequestDispatching(read) status=%ld", status);
			return status;
		}
		// Create IO queue for writing packets
		WDF_IO_QUEUE_CONFIG_INIT(&qConfig, WdfIoQueueDispatchSequential);
		qConfig.EvtIoWrite = EvtIoWrite;
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &writeQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%ld", status);
			return status;
		}
		WdfObjectGet_QueueContextSpace(writeQueue)->queue = &writeQueue;
		if (NTSTATUS status = WdfDeviceConfigureRequestDispatching(hDevice, writeQueue, WdfRequestTypeWrite);
			status != STATUS_SUCCESS)
		{
			DbgPrint("WdfDeviceConfigureRequestDispatching(write) status=%ld", status);
			return status;
		}
		// Initialize WFP callout
		PDEVICE_OBJECT deviceObject = WdfDeviceWdmGetDeviceObject(hDevice);
		FWPS_CALLOUT0 callout{
			PacketDriverCalloutGuid,
			0,
			packetClassifyFn,
			nullptr,
			nullptr
		};
		DeviceContextSpace* deviceContext = WdfObjectGet_DeviceContextSpace(hDevice);
		NTSTATUS status = STATUS_SUCCESS;
		if (status == STATUS_SUCCESS &&
			(status = FwpsCalloutRegister0(deviceObject, &callout, &deviceContext->calloutId)) != STATUS_SUCCESS)
		{
			DbgPrint("FwpsCalloutRegister0 status=%ld", status);
		} else
			deviceContext->calloutRegistered = true;
		if (status == STATUS_SUCCESS &&
			(status = FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &injectionHandleIpv4))
			!= STATUS_SUCCESS)
		{
			DbgPrint("FwpsInjectionHandleCreate0(IPv4) status=%ld", status);
		} else
			deviceContext->injectionHandleIpv4 = &injectionHandleIpv4;
		if (status == STATUS_SUCCESS &&
			(status = FwpsInjectionHandleCreate0(AF_INET6, FWPS_INJECTION_TYPE_NETWORK, &injectionHandleIpv6))
			!= STATUS_SUCCESS)
		{
			DbgPrint("FwpsInjectionHandleCreate0(IPv6) status=%ld", status);
		} else
			deviceContext->injectionHandleIpv6 = &injectionHandleIpv6;
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
		DbgPrint("DriverEntry status=%ld\n", status);
		return status;
	}
}