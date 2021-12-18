#include <ntddk.h>
#include <wdf.h>

extern "C" {
	DRIVER_INITIALIZE DriverEntry;
	EVT_WDF_DRIVER_DEVICE_ADD PacketDriverEvtDeviceAdd;

	NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
	{
		WDF_DRIVER_CONFIG config;
		WDF_DRIVER_CONFIG_INIT(&config, PacketDriverEvtDeviceAdd);
		NTSTATUS status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
		DbgPrint("DriverEntry status=%ld\n", status);
		return status;
	}

	NTSTATUS PacketDriverEvtDeviceAdd([[maybe_unused]] WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
	{
		WDFDEVICE hDevice;
		NTSTATUS status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);
		DbgPrint("PacketDriverEvtDeviceAdd status=%ld\n", status);
		return status;
	}
}