#include "Driver.h"

#include <ntddk.h>
#include <wdf.h>

namespace {

	LONGLONG maxRead = -1;
	LONGLONG maxWrite = -1;
	char filler = '\0';

	ZeroDriverStats stats{};

	void EvtIoRead([[maybe_unused]] WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
	{
		ULONG_PTR transferred = Length;
		if (maxRead >= 0 && transferred > size_t(maxRead))
			transferred = maxRead;
		void* bufObj;
		if (NTSTATUS status = WdfRequestRetrieveOutputBuffer(Request, transferred, &bufObj, nullptr);
			status != STATUS_SUCCESS)
		{
			DbgPrint("WdfRequestRetrieveOutputBuffer status=%ld", status);
			WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
			return;
		}
		RtlFillMemory(bufObj, transferred, filler);
		++stats.readRequests;
		stats.readRequests += transferred;
		WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, transferred);
	}

	void EvtIoWrite([[maybe_unused]] WDFQUEUE Queue, WDFREQUEST Request, size_t Length)
	{
		ULONG_PTR transferred = Length;
		if (maxWrite >= 0 && transferred > size_t(maxWrite))
			transferred = maxWrite;
		++stats.writeRequests;
		stats.writeRequests += transferred;
		WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, transferred);
	}

	void EvtIoDeviceControl([[maybe_unused]] WDFQUEUE Queue, WDFREQUEST Request, [[maybe_unused]] size_t OutputBufferLength,
		[[maybe_unused]] size_t InputBufferLength, ULONG IoControlCode)
	{
		ULONG_PTR transferred = 0;
		switch (IoControlCode) {
		case IOCTL_ZERODRIVER_SET_MAX_READ:
		{
			WDFMEMORY memory;
			if (NTSTATUS status = WdfRequestRetrieveInputMemory(Request, &memory); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_ZERODRIVER_SET_MAX_READ WdfRequestRetrieveInputMemory status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			if (NTSTATUS status = WdfMemoryCopyToBuffer(memory, 0, &maxRead, sizeof(maxRead)); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_ZERODRIVER_SET_MAX_READ WdfMemoryCopyToBuffer status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			break;
		}
		case IOCTL_ZERODRIVER_SET_MAX_WRITE:
		{
			WDFMEMORY memory;
			if (NTSTATUS status = WdfRequestRetrieveInputMemory(Request, &memory); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_ZERODRIVER_SET_MAX_WRITE WdfRequestRetrieveInputMemory status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			if (NTSTATUS status = WdfMemoryCopyToBuffer(memory, 0, &maxWrite, sizeof(maxWrite)); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_ZERODRIVER_SET_MAX_WRITE WdfMemoryCopyToBuffer status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			break;
		}
		case IOCTL_ZERODRIVER_SET_FILLER:
		{
			WDFMEMORY memory;
			if (NTSTATUS status = WdfRequestRetrieveInputMemory(Request, &memory); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_ZERODRIVER_SET_FILLER WdfRequestRetrieveInputMemory status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			if (NTSTATUS status = WdfMemoryCopyToBuffer(memory, 0, &filler, sizeof(filler)); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_ZERODRIVER_SET_FILLER WdfMemoryCopyToBuffer status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			break;
		}
		case IOCTL_ZERODRIVER_GET_STATS:
		case IOCTL_ZERODRIVER_GET_AND_RESET_STATS:
		{
			WDFMEMORY memory;
			if (NTSTATUS status = WdfRequestRetrieveOutputMemory(Request, &memory); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_ZERODRIVER_SET_FILLER WdfRequestRetrieveInputMemory status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			if (NTSTATUS status = WdfMemoryCopyFromBuffer(memory, 0, &stats, sizeof(stats)); status != STATUS_SUCCESS) {
				DbgPrint("IOCTL_ZERODRIVER_SET_FILLER WdfMemoryCopyFromBuffer status=%ld", status);
				WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
				return;
			}
			if (IoControlCode == IOCTL_ZERODRIVER_GET_STATS)
				break;
			[[fallthrough]];
		}
		case IOCTL_ZERODRIVER_RESET_STATS:
			stats = {};
			break;
		default:
			DbgPrint("Invalid IoControlCode=%lu", IoControlCode);
			WdfRequestCompleteWithInformation(Request, STATUS_UNSUCCESSFUL, 0);
			return;
		}
		WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, transferred);
	}

	NTSTATUS EvtDeviceAdd([[maybe_unused]] WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
	{
		DECLARE_CONST_UNICODE_STRING(deviceName, ZERODRIVER_DEVICE_ZERO);
		if (NTSTATUS status = WdfDeviceInitAssignName(DeviceInit, &deviceName); status != STATUS_SUCCESS) {
			DbgPrint("WdfDeviceInitAssignName status=%ld", status);
			return status;
		}
		WDF_IO_TYPE_CONFIG ioConfig;
		WDF_IO_TYPE_CONFIG_INIT(&ioConfig);
		ioConfig.ReadWriteIoType = WdfDeviceIoDirect;
		WdfDeviceInitSetIoTypeEx(DeviceInit, &ioConfig);
		WDFDEVICE hDevice;
		NTSTATUS result = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);
		DbgPrint("ZeroDriverEvtDeviceAdd status=%ld\n", result);
		WDF_IO_QUEUE_CONFIG qConfig;
		WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qConfig, WdfIoQueueDispatchSequential);
		qConfig.AllowZeroLengthRequests = true;
		qConfig.EvtIoRead = EvtIoRead;
		qConfig.EvtIoWrite = EvtIoWrite;
		qConfig.EvtIoDeviceControl = EvtIoDeviceControl;
		WDF_OBJECT_ATTRIBUTES qAttr;
		WDF_OBJECT_ATTRIBUTES_INIT(&qAttr);
		qAttr.SynchronizationScope = WdfSynchronizationScopeQueue;
		WDFQUEUE hQueue;
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, &qAttr, &hQueue);
			status != STATUS_SUCCESS)
		{
			DbgPrint("WdfIoQueueCreate status=%ld", status);
			return status;
		}
		return result;
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