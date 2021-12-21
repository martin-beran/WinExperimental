#include <ntddk.h>
#include <wdf.h>

namespace {
	
	void EvtIoRead(WDFQUEUE /*Queue*/, WDFREQUEST /*Request*/, size_t /*Length*/)
	{
	}

	void EvtIoWrite(WDFQUEUE /*Queue*/, WDFREQUEST /*Request*/, size_t /*Length*/)
	{
	}

	void EvtIoDeviceControl(WDFQUEUE /*Queue*/, WDFREQUEST /*Request*/, size_t /*OutputBufferLength*/,
		size_t /*InputBufferLength*/, ULONG /*IoControlCode*/)
	{
	}

	NTSTATUS EvtDeviceAdd([[maybe_unused]] WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
	{
		DECLARE_CONST_UNICODE_STRING(deviceName, L"\\Device\\PacketDriver");
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
		DbgPrint("PacketDriverEvtDeviceAdd status=%ld\n", result);
		WDF_IO_QUEUE_CONFIG qConfig;
		WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&qConfig, WdfIoQueueDispatchSequential);
		qConfig.AllowZeroLengthRequests = true;
		qConfig.EvtIoRead = EvtIoRead;
		qConfig.EvtIoWrite = EvtIoWrite;
		qConfig.EvtIoDeviceControl = EvtIoDeviceControl;
		WDFQUEUE hQueue;
		if (NTSTATUS status = WdfIoQueueCreate(hDevice, &qConfig, WDF_NO_OBJECT_ATTRIBUTES, &hQueue);
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