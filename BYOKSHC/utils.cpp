#include "utils.h"


EZPDB loadKernelOffsets() {
    std::string kernel = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
    std::string pdbPath = EzPdbDownload(kernel);

    if (pdbPath.empty())
    {
        std::cout << "download pdb failed " << GetLastError() << std::endl;;
    }

    EZPDB pdb;
    if (!EzPdbLoad(pdbPath, &pdb))
    {
        std::cout << "load pdb failed " << GetLastError() << std::endl;
    }


    return pdb;
}


//PVOID GetNtoskrnlBaseAddress()
//{
//    NTSTATUS status;
//    ULONG returnLength = 0;
//    PSYSTEM_MODULE_INFORMATION moduleInfo = NULL;
//    PVOID ntoskrnlBase = NULL;
//
//    // Dynamically load the NtQuerySystemInformation function from ntdll.dll
//    // GetModuleHandle retrieves the handle to ntdll.dll (already loaded in every process)
//    // GetProcAddress retrieves the address of the specified function
//    NtQuerySystemInformation_t NtQuerySystemInformation =
//        (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
//    if (!NtQuerySystemInformation) {
//        printf("Failed to locate NtQuerySystemInformation.\n");
//        return NULL;
//    }
//
//    // Step 1: Query the required buffer size for the system module information
//    status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &returnLength);
//    if (status != STATUS_INFO_LENGTH_MISMATCH) {
//        printf("Failed to query system information size.\n");
//        return NULL;
//    }
//
//    // Step 2: Allocate memory for the module information based on the size returned
//    moduleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(returnLength);
//    if (!moduleInfo) {
//        printf("Failed to allocate memory for module information.\n");
//        return NULL;
//    }
//
//
//    // Step 3: Query the actual system module information with the allocated buffer
//    status = NtQuerySystemInformation(SystemModuleInformation, moduleInfo, returnLength, &returnLength);
//    if (status != STATUS_SUCCESS) {
//        printf("Failed to query system module information.\n");
//        free(moduleInfo);
//        return NULL;
//    }
//
//
//    // Extract the base address of the first module in the list
//    // the first entry (Modules[0]) is typically ntoskrnl.exe, the kernel image
//    ntoskrnlBase = moduleInfo->Modules[0].ImageBase;
//
//    // Clean up and return
//    free(moduleInfo);
//    return ntoskrnlBase;
//}
//


ULONG_PTR GetKernelBaseAddress() {
	ULONG_PTR pKernelBaseAddress = 0;
	LPVOID* lpImageBase = NULL;
	DWORD dwBytesNeeded = 0;

	// first call calculates the exact size needed to read all the data
	if (!EnumDeviceDrivers(NULL, 0, &dwBytesNeeded)) {
		wprintf(L"[-] Couldn't EnumDeviceDrivers.\n");
		return pKernelBaseAddress;
	}

	// allocate enough memory to read all data from EnumDeviceDrivers
	if (!(lpImageBase = (LPVOID*)HeapAlloc(GetProcessHeap(), 0, dwBytesNeeded))) {
		wprintf(L"[-] Couldn't allocate heap for lpImageBase.\n");
		if (lpImageBase)
			HeapFree(GetProcessHeap(), 0, lpImageBase);

		return pKernelBaseAddress;
	}

	if (!EnumDeviceDrivers(lpImageBase, dwBytesNeeded, &dwBytesNeeded)) {
		wprintf(L"[-] Couldn't EnumDeviceDrivers.\n");
		if (lpImageBase)
			HeapFree(GetProcessHeap(), 0, lpImageBase);

		return pKernelBaseAddress;
	}

	// the first entry in the list is the kernel
	pKernelBaseAddress = ((ULONG_PTR*)lpImageBase)[0];
	wprintf(L"[*] KernelBaseAddress: %llx\n", pKernelBaseAddress);

	return pKernelBaseAddress;
}