//
// Created by Anonymous275 on 9/9/2021.
//

#include <windows.h>
#include <imagehlp.h>
#include <tlhelp32.h>
#include <strsafe.h>
#include <cstdint>
#include <string>
#include <atomic>
#include <array>

std::string crash_file;

template <typename I>
std::string HexString(I w) {
    static const char* digits = "0123456789ABCDEF";
    const size_t hex_len = sizeof(I)<<1;
    std::string rc(hex_len, '0');
    for (size_t i=0, j=(hex_len-1)*4 ; i<hex_len; ++i,j-=4)
        rc[i] = digits[(w>>j) & 0x0f];
    return rc;
}


std::atomic<int64_t> Offset{0};
std::atomic<bool> Sym{false};

void watchdog_setOffset(int64_t Off) {
    Offset.store(Off);
}

void notify(const char* msg) {
    HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdOut != nullptr && stdOut != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteConsoleA(stdOut, "[WATCHDOG] ", 11, &written, nullptr);
        WriteConsoleA(stdOut, msg, DWORD(strlen(msg)), &written, nullptr);
        WriteConsoleA(stdOut, "\n", 1, &written, nullptr);
    }
}

std::string getFunctionSym(DWORD64 Address) {
    if(!Sym.load()) {
        return {};
    }
    static HANDLE process = GetCurrentProcess();
    DWORD64 symDisplacement = 0;
    std::string Result;
    TCHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    memset(&buffer,0, sizeof(buffer));
    auto pSymbolInfo = (PSYMBOL_INFO)buffer;
    pSymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbolInfo->MaxNameLen	= MAX_SYM_NAME;
    if (SymFromAddr(process, Address + Offset, &symDisplacement, pSymbolInfo)) {
        Result.append(pSymbolInfo->Name);
    }
    return Result;
}


std::string getLocation(DWORD64 Address){
    if(!Sym.load()) {
        return "unknown";
    }
    DWORD pdwDisplacement = 0;
    IMAGEHLP_LINE64 line{sizeof(IMAGEHLP_LINE64)};
    SymGetLineFromAddr64(GetCurrentProcess(), Address + Offset, &pdwDisplacement, &line);
    char* Name = nullptr;
    if(line.FileName) {
        Name = strrchr(line.FileName, '\\');
    }
    std::string Result;
    if(Name){
        Result.append(Name+1);
        char buffer[20];
        auto n = sprintf(buffer, ":%lu", line.LineNumber);
        Result.append(buffer, n);
        return Result;
    } else {
        return "unknown";
    }
}
std::string getFunctionDetails(size_t Address) {
    return getFunctionSym(Address);
}
std::string getCrashLocation(size_t Address) {
    return getLocation(Address);
}

void InitSym(const char* PDBLocation) {
    SymInitialize(GetCurrentProcess(), PDBLocation, TRUE);
    Sym.store(true);
}

void write_report(const std::string& Report) {
    HANDLE hFile = CreateFile(crash_file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        notify("Failed to open crash file for writing!");
        return;
    }
    DWORD dwBytesWritten = 0;
    auto Flag = WriteFile(hFile, Report.c_str(), DWORD(Report.size()), &dwBytesWritten, nullptr);
    if (Flag == FALSE) {
        notify("Failed to write to crash file!");
    }
    CloseHandle(hFile);
}

std::string getStack(HANDLE hThread) {
    BOOL                result;
    HANDLE              process;
    CONTEXT             context;
    STACKFRAME64        stack;

    RtlCaptureContext(&context);
    memset(&stack, 0, sizeof(STACKFRAME64));

    process                = GetCurrentProcess();
    stack.AddrPC.Offset    = context.Rip;
    stack.AddrPC.Mode      = AddrModeFlat;
    stack.AddrStack.Offset = context.Rsp;
    stack.AddrStack.Mode   = AddrModeFlat;
    stack.AddrFrame.Offset = context.Rbp;
    stack.AddrFrame.Mode   = AddrModeFlat;
    std::string Report("Stack for thread ID: ");
    Report += std::to_string(GetThreadId(hThread)) + '\n';
    do {
        result = StackWalk64(
                IMAGE_FILE_MACHINE_AMD64,
                process,
                hThread,
                &stack,
                &context,
                nullptr,
                SymFunctionTableAccess64,
                SymGetModuleBase64,
                nullptr
                );

        std::string FunctionSym(getFunctionSym(stack.AddrPC.Offset));
        std::string Location;
        if(!FunctionSym.empty()) {
            Location = getLocation(stack.AddrPC.Offset);
            Report += FunctionSym + " | " + Location + '\n';
        } else {
            Report += std::to_string(stack.AddrPC.Offset) + '\n';
        }

    }while(result);
    return Report;
}


void generate_crash_report(uint32_t Code, size_t Address) {
    notify("generating crash report, please wait");
    std::string Report("crash code ");
    Report += HexString(Code) + " at " + HexString(Address + Offset) + '\n';
    if(Address) {
        Report += "origin and line number -> " + getLocation(Address) + '\n';
    }
    Report += "Reports: \n";
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(h, &te)) {
            do {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                sizeof(te.th32OwnerProcessID)) {
                    Report += getStack( OpenThread(READ_CONTROL, FALSE, te.th32ThreadID));
                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }
    write_report(Report);
    notify("crash report generated");
}

LONG WINAPI CrashHandler(EXCEPTION_POINTERS* p) {
    notify("CAUGHT EXCEPTION!");
    generate_crash_report(p->ExceptionRecord->ExceptionCode, size_t(p->ExceptionRecord->ExceptionAddress));
    return EXCEPTION_EXECUTE_HANDLER;
}

void watchdog_init(const std::string& crashFile, const char* SpecificPDBLocation, bool Symbols) {
    if(Symbols)SymInitialize(GetCurrentProcess(), SpecificPDBLocation, TRUE);
    Sym.store(Symbols);
    SetUnhandledExceptionFilter(CrashHandler);
    crash_file = crashFile;
    notify("initialized!");
}