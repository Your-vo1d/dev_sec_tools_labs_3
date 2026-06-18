#include <windows.h>
#include <stdio.h>

// Если определён — защищаем сам текущий процесс (self-relaunch).
// Убери этот define, чтобы вместо этого запустить сторонний процесс с защитой.
#define LOCAL_BLOCKDLLPOLICY

#ifdef LOCAL_BLOCKDLLPOLICY
// Аргумент, который процесс передаёт сам себе при повторном запуске,
// сигнализируя, что он уже работает с митигацией DLL-инъекций.
#define STOP_ARG "xakep"
#endif

/*
 * CreateProcessWithBlockDllPolicy — запускает процесс с политикой
 * PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON,
 * которая запрещает загрузку DLL, не подписанных Microsoft.
 *
 * Алгоритм:
 *   1. InitializeProcThreadAttributeList (2 вызова: сначала узнать размер буфера,
 *      затем инициализировать его).
 *   2. UpdateProcThreadAttribute — записать политику в атрибут-лист.
 *   3. CreateProcessA с флагом EXTENDED_STARTUPINFO_PRESENT.
 */
BOOL CreateProcessWithBlockDllPolicy(
    IN LPSTR lpProcessPath,
    OUT DWORD *dwProcessId,
    OUT HANDLE *hProcess,
    OUT HANDLE *hThread)
{
    STARTUPINFOEXA SiEx = {0};
    PROCESS_INFORMATION Pi = {0};
    SIZE_T sAttrSize = NULL;

    if (lpProcessPath == NULL)
        return FALSE;

    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

    // Первый вызов: узнать необходимый размер буфера.
    InitializeProcThreadAttributeList(NULL, 1, 0, &sAttrSize);

    LPPROC_THREAD_ATTRIBUTE_LIST pAttrBuf =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);

    // Второй вызов: инициализировать буфер.
    if (!InitializeProcThreadAttributeList(pAttrBuf, 1, 0, &sAttrSize))
    {
        printf("[!] InitializeProcThreadAttributeList Failed With Error : %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pAttrBuf);
        return FALSE;
    }

    DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    if (!UpdateProcThreadAttribute(
            pAttrBuf,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &dwPolicy,
            sizeof(DWORD64),
            NULL,
            NULL))
    {
        printf("[!] UpdateProcThreadAttribute Failed With Error : %d\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrBuf);
        HeapFree(GetProcessHeap(), 0, pAttrBuf);
        return FALSE;
    }

    SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuf;

    if (!CreateProcessA(
            NULL,
            lpProcessPath,
            NULL,
            NULL,
            FALSE,
            EXTENDED_STARTUPINFO_PRESENT,
            NULL,
            NULL,
            &SiEx.StartupInfo,
            &Pi))
    {
        printf("[!] CreateProcessA Failed With Error : %d\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrBuf);
        HeapFree(GetProcessHeap(), 0, pAttrBuf);
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    DeleteProcThreadAttributeList(pAttrBuf);
    HeapFree(GetProcessHeap(), 0, pAttrBuf);

    if (*dwProcessId != 0 && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

int main(int argc, char *argv[])
{
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

#ifdef LOCAL_BLOCKDLLPOLICY

    if (argc == 2 && (strcmp(argv[1], STOP_ARG) == 0))
    {
        // Процесс запущен с митигацией — основная логика приложения здесь.
        printf("[+] Process Is Now Protected With The Block Dll Policy\n");

        // Здесь размещается реальный код защищённого приложения.
        // WaitForSingleObject на псевдо-хендл текущего процесса используется
        // только для демонстрации: держит процесс живым для проверки в Process Hacker.
        WaitForSingleObject((HANDLE)-1, INFINITE);
    }
    else
    {
        // STOP_ARG отсутствует — процесс запущен напрямую без митигации.
        // Перезапускаем сами себя через CreateProcess с атрибутом блокировки DLL.
        printf("[!] Local Process Is Not Protected With The Block Dll Policy\n");

        CHAR pcFilename[MAX_PATH * 2];
        if (!GetModuleFileNameA(NULL, (LPSTR)&pcFilename, MAX_PATH * 2))
        {
            printf("[!] GetModuleFileNameA Failed With Error : %d\n", GetLastError());
            return -1;
        }

        DWORD dwBufferSize = (DWORD)(lstrlenA(pcFilename) + lstrlenA(STOP_ARG) + 0xFF);
        CHAR *pcBuffer = (CHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
        if (!pcBuffer)
            return -1;

        // Формируем командную строку: "<путь к exe> <STOP_ARG>"
        sprintf_s(pcBuffer, dwBufferSize, "%s %s", pcFilename, STOP_ARG);

        if (!CreateProcessWithBlockDllPolicy(pcBuffer, &dwProcessId, &hProcess, &hThread))
        {
            HeapFree(GetProcessHeap(), 0, pcBuffer);
            return -1;
        }

        HeapFree(GetProcessHeap(), 0, pcBuffer);
        printf("[i] Process Created With Pid %d\n", dwProcessId);
    }

#else

    // Режим запуска стороннего процесса с защитой от DLL-инъекций.
    if (!CreateProcessWithBlockDllPolicy(
            (LPSTR) "C:\\Windows\\System32\\RuntimeBroker.exe",
            &dwProcessId, &hProcess, &hThread))
    {
        return -1;
    }
    printf("[i] Process Created With Pid %d\n", dwProcessId);

#endif

    return 0;
}
