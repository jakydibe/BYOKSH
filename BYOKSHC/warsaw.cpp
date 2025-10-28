#include "utils.h"


BOOL terminatePrimitive(HANDLE hDevice, DWORD pid) {
    DWORD bytesReturned = 0;
    // Assuming the driver expects the PID's size as the input parameter.
    BOOL result = DeviceIoControl(hDevice, IOCTL_TERM, &pid, 1036, NULL, 0, &bytesReturned, NULL);
    if (!result) {
        printf("[!] Error terminating process: %d\n", GetLastError());
    }
    else {
        printf("[+] Process terminated successfully.\n");
    }

    return result;
}
