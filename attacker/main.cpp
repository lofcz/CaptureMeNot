#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <TlHelp32.h>

#ifndef WDA_NONE
#define WDA_NONE 0x00000000
#endif

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

struct InjectionData {
    HWND hwnd;
    DWORD affinity;
    BOOL (WINAPI *SetWindowDisplayAffinity)(HWND, DWORD);
};

DWORD WINAPI RemoteThreadProc(LPVOID lpParameter) {
    InjectionData* data = (InjectionData*)lpParameter;
    BOOL result = data->SetWindowDisplayAffinity(data->hwnd, data->affinity);
    return result ? 1 : 0;
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    return processId;
}

struct FindWindowData {
    const wchar_t* processName;
    std::vector<HWND> foundWindows;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    FindWindowData* data = reinterpret_cast<FindWindowData*>(lParam);

    if (!IsWindowVisible(hwnd)) {
        return TRUE;
    }

    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess) {
        wchar_t processPath[MAX_PATH];
        DWORD size = MAX_PATH;

        if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
            wchar_t* fileName = wcsrchr(processPath, L'\\');
            if (fileName) {
                fileName++;

                if (_wcsicmp(fileName, data->processName) == 0) {
                    data->foundWindows.push_back(hwnd);
                }
            }
        }

        CloseHandle(hProcess);
    }

    return TRUE;
}

BOOL InjectSetWindowDisplayAffinity(DWORD processId, HWND hwnd, DWORD affinity) {
    BOOL success = FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                 PROCESS_VM_WRITE | PROCESS_VM_READ |
                                 PROCESS_QUERY_INFORMATION, FALSE, processId);

    if (hProcess) {
        InjectionData localData;
        localData.hwnd = hwnd;
        localData.affinity = affinity;
        localData.SetWindowDisplayAffinity = (BOOL (WINAPI *)(HWND, DWORD))
                                            GetProcAddress(GetModuleHandleA("user32.dll"),
                                                          "SetWindowDisplayAffinity");

        LPVOID remoteData = VirtualAllocEx(hProcess, NULL, sizeof(InjectionData),
                                          MEM_COMMIT, PAGE_READWRITE);

        if (remoteData) {
            if (WriteProcessMemory(hProcess, remoteData, &localData, sizeof(InjectionData), NULL)) {

                SIZE_T codeSize = 1024;
                LPVOID remoteCode = VirtualAllocEx(hProcess, NULL, codeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                if (remoteCode) {
                    if (WriteProcessMemory(hProcess, remoteCode,  (LPCVOID)RemoteThreadProc, codeSize, NULL)) {
                        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                                          (LPTHREAD_START_ROUTINE)remoteCode,
                                                          remoteData, 0, NULL);

                        if (hThread) {
                            WaitForSingleObject(hThread, INFINITE);

                            DWORD exitCode;
                            if (GetExitCodeThread(hThread, &exitCode)) {
                                success = (exitCode == 1);
                            }

                            CloseHandle(hThread);
                        }
                    }

                    VirtualFreeEx(hProcess, remoteCode, 0, MEM_RELEASE);
                }
            }

            VirtualFreeEx(hProcess, remoteData, 0, MEM_RELEASE);
        }

        CloseHandle(hProcess);
    }

    return success;
}

BOOL TryChangeWindowAffinity(HWND hwnd, DWORD targetAffinity) {

    // method 1: call SetWindowDisplayAffinity directly
    if (SetWindowDisplayAffinity(hwnd, targetAffinity)) {
        std::cout << "Metoda 1 úspěšná: Přímé volání SetWindowDisplayAffinity" << std::endl;
        return TRUE;
    }

    DWORD error = GetLastError();
    std::cout << "Metoda 1 selhala s chybou: 0x" << std::hex << error << std::endl;

    // method 2: AttachThreadInput
    DWORD currentThreadId = GetCurrentThreadId();
    DWORD windowThreadId = GetWindowThreadProcessId(hwnd, NULL);

    if (AttachThreadInput(currentThreadId, windowThreadId, TRUE)) {
        BOOL result = SetWindowDisplayAffinity(hwnd, targetAffinity);
        AttachThreadInput(currentThreadId, windowThreadId, FALSE);

        if (result) {
            std::cout << "Metoda 2 úspěšná: AttachThreadInput" << std::endl;
            return TRUE;
        }

        error = GetLastError();
        std::cout << "Metoda 2 selhala s chybou: 0x" << std::hex << error << std::endl;
    }

    // method 3: inject
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    if (InjectSetWindowDisplayAffinity(processId, hwnd, targetAffinity)) {
        std::cout << "Metoda 3 úspěšná: Injektování kódu" << std::endl;
        return TRUE;
    }

    std::cout << "Metoda 3 selhala" << std::endl;
    return FALSE;
}

int main() {

    FindWindowData data;
    data.processName = L"Affinity.exe";

    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&data));

    if (data.foundWindows.empty()) {
        std::cout << "Okno aplikace Affinity.exe nebylo nalezeno." << std::endl;
        std::cout << "Stiskněte libovolnou klávesu pro ukončení..." << std::endl;
        std::cin.get();
        return 1;
    }

    std::cout << "Nalezeno " << data.foundWindows.size() << " oken aplikace Affinity.exe." << std::endl;

    for (HWND hwnd : data.foundWindows) {
        DWORD currentAffinity = 0;
        BOOL result = GetWindowDisplayAffinity(hwnd, &currentAffinity);

        if (result) {
            if (currentAffinity == WDA_EXCLUDEFROMCAPTURE) {
                std::cout << "Aktuální afinita okna: WDA_EXCLUDEFROMCAPTURE" << std::endl;
            } else if (currentAffinity == WDA_NONE) {
                std::cout << "Aktuální afinita okna: WDA_NONE (normální)" << std::endl;
            } else {
                std::cout << "Aktuální afinita okna: 0x" << std::hex << currentAffinity << std::endl;
            }

            if (TryChangeWindowAffinity(hwnd, WDA_NONE)) {
                std::cout << "Afinita okna úspěšně změněna na WDA_NONE." << std::endl;
            } else {
                std::cout << "Všechny metody pro změnu afinity selhaly." << std::endl;

                DWORD processId;
                GetWindowThreadProcessId(hwnd, &processId);

                std::cout << "Zkouším ukončit a restartovat proces..." << std::endl;

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
                if (hProcess) {
                    wchar_t processPath[MAX_PATH];
                    DWORD size = MAX_PATH;

                    if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
                        HANDLE hTerminate = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
                        if (hTerminate) {
                            if (TerminateProcess(hTerminate, 0)) {
                                std::cout << "Proces úspěšně ukončen." << std::endl;

                                Sleep(1000);

                                STARTUPINFOW si = { sizeof(si) };
                                PROCESS_INFORMATION pi;

                                if (CreateProcessW(processPath, NULL, NULL, NULL, FALSE,
                                                 CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                                    std::cout << "Proces úspěšně restartován." << std::endl;
                                    CloseHandle(pi.hProcess);
                                    CloseHandle(pi.hThread);
                                } else {
                                    std::cout << "Nelze restartovat proces: 0x" << std::hex << GetLastError() << std::endl;
                                }
                            } else {
                                std::cout << "Nelze ukončit proces: 0x" << std::hex << GetLastError() << std::endl;
                            }
                            CloseHandle(hTerminate);
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        } else {
            DWORD error = GetLastError();
            std::cout << "Chyba při získávání afinity okna: 0x" << std::hex << error << std::endl;
        }
    }

    std::cout << "Stiskněte libovolnou klávesu pro ukončení..." << std::endl;
    std::cin.get();

    return 0;
}
