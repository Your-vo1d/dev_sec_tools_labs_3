#include <windows.h>
#include <winerror.h>
#include <psapi.h>

// Функция, которая выполняется при загрузке DLL в процесс
void AttackProcess()
{
    char szProcessName[128];
    GetModuleBaseNameA(GetCurrentProcess(), NULL, szProcessName, sizeof(szProcessName));
    MessageBoxA(NULL, "BOOM!", szProcessName, MB_OK);
}

// Точка входа в DLL
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        AttackProcess(); // исправлено: вызов правильной функции
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        if (lpvReserved != nullptr)
            break; // не выполняем очистку при завершении процесса
        break;
    }
    return TRUE;
}