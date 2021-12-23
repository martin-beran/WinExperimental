#include "PacketDriver.h"

#include <ntddk.h>
#include <wdf.h>

namespace {

	PacketDriverStats stats;

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

	void EvtIoReadReady(WDFQUEUE /*Queue*/, [[maybe_unused]] WDFCONTEXT /*Context*/)
	{
		// TODO
	}

	void EvtIoWrite([[maybe_unused]] WDFQUEUE Queue, WDFREQUEST /*Request*/, size_t /*Length*/)
	{
		// TODO
	}

	NTSTATUS EvtDeviceAdd([[maybe_unused]] WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
	{
		// Create device
		DECLARE_CONST_UNICODE_STRING(deviceName, PACKETDRIVER_DEVICE);
		if (NTSTATUS status = WdfDeviceInitAssignName(DeviceInit, &deviceName); status != STATUS_SUCCESS) {
			DbgPrint("WdfDeviceInitAssignName status=%ld", status);
			return status;
		}
		WDF_IO_TYPE_CONFIG ioConfig;
		WDF_IO_TYPE_CONFIG_INIT(&ioConfig);
		ioConfig.ReadWriteIoType = WdfDeviceIoDirect;
		WdfDeviceInitSetIoTypeEx(DeviceInit, &ioConfig);
		WDFDEVICE hDevice;
		if (NTSTATUS status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice); status != STATUS_SUCCESS) {
			DbgPrint("EvtDeviceAdd status=%ld\n", status);
			return status;
		}
		// Create IO queues
		WDF_OBJECT_ATTRIBUTES qAttr;
		WDF_OBJECT_ATTRIBUTES_INIT(&qAttr);
		qAttr.SynchronizationScope = WdfSynchronizationScopeQueue;
		WDFQUEUE hQueue;
		// Create default IO queue, used for IOCTL requests
		WDF_IO_QUEUE_CONFIG qConfig;
		WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qConfig, WdfIoQueueDispatchSequential);
		qConfig.EvtIoDeviceControl = EvtIoDeviceControl;
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &hQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%ld", status);
			return status;
		}
		// Create IO queue for reading packets
		WDF_IO_QUEUE_CONFIG_INIT(&qConfig, WdfIoQueueDispatchManual);
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &hQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%ld", status);
			return status;
		}
		if (NTSTATUS status = WdfIoQueueReadyNotify(hQueue, EvtIoReadReady, nullptr); status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueReadyNotify(read) status=%ld", status);
			return status;
		}
		if (NTSTATUS status = WdfDeviceConfigureRequestDispatching(hDevice, hQueue, WdfRequestTypeRead);
			status != STATUS_SUCCESS)
		{
			DbgPrint("WdfDeviceConfigureRequestDispatching(read) status=%ld", status);
			return status;
		}
		// Create IO queue for writing packets
		WDF_IO_QUEUE_CONFIG_INIT(&qConfig, WdfIoQueueDispatchSequential);
		qConfig.EvtIoWrite = EvtIoWrite;
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &hQueue);	status != STATUS_SUCCESS) {
			DbgPrint("WdfIoQueueCreate(device control) status=%ld", status);
			return status;
		}
		if (NTSTATUS status = WdfDeviceConfigureRequestDispatching(hDevice, hQueue, WdfRequestTypeWrite);
			status != STATUS_SUCCESS)
		{
			DbgPrint("WdfDeviceConfigureRequestDispatching(write) status=%ld", status);
			return status;
		}
		return STATUS_SUCCESS;
	}
}

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