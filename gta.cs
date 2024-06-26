#include <vector>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <codecvt>
#include <sstream>
#include <iostream>

using offsets = std::vector<uint64_t>;

class Memory {
private:
    HANDLE pHandle;
    int pID;
    uint64_t BaseAddress;
    std::string FilePath;
    uint64_t iSize;

public:
    Memory(const char* processName, const char* moduleName = nullptr);
    ~Memory();
    bool isHex(char c);
    std::string getFilePath();
    uint64_t getBaseAddress();
    int getProcessId();
    uint64_t getImageSize();
    HANDLE getHandle();
    void initVars(MODULEENTRY32* m);
    void getProcess(const char* processName, PROCESSENTRY32* process);
    void getModule(const char* moduleName, MODULEENTRY32* module, PROCESSENTRY32* process);
    uint64_t getAddress(uint64_t Address, offsets offsets = {});
    uint64_t patternScan(char* sig, std::string pattern, uint64_t startAddress = 0);
    uint64_t patternScan(const std::string& pattern, uint64_t startAddress = 0);
    bool createPattern(const std::string& pattern, std::string& pattern_result, std::string& mask_result);

    template<typename T> T read(uint64_t Address, offsets offsets = {}) {
        T ret;
        if (Address == 0)
            return ret;
        uint64_t nAddress = getAddress(Address, offsets);
        ReadProcessMemory(pHandle, (void*)nAddress, &ret, sizeof(T), 0);
        return ret;
    }

    template<typename T> void write(uint64_t Address, T value, offsets offsets = {}) {
        uint64_t nAddress = getAddress(Address, offsets);
        WriteProcessMemory(pHandle, (void*)nAddress, &value, sizeof(T), 0);
    }

    std::string readString(uint64_t Address, int size, offsets offsets = {});
    void writeString(uint64_t Address, std::string& str, offsets offsets = {});
};

Memory::Memory(const char* processName, const char* moduleName) {
    PROCESSENTRY32 pe32;
    MODULEENTRY32 pe_module;

    getProcess(processName, &pe32);
    getModule(moduleName == nullptr ? processName : moduleName, &pe_module, &pe32);
    initVars(&pe_module);
    pHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
}

Memory::~Memory() {
    CloseHandle(pHandle);
}

std::string Memory::getFilePath() {
    return FilePath;
}

uint64_t Memory::getBaseAddress() {
    return BaseAddress;
}

int Memory::getProcessId() {
    return pID;
}

uint64_t Memory::getImageSize() {
    return iSize;
}

HANDLE Memory::getHandle() {
    return pHandle;
}

void Memory::initVars(MODULEENTRY32* m) {
#ifndef _MBCS
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> w2sConverter;
    FilePath = w2sConverter.to_bytes(m->szExePath).c_str();
#else
    FilePath = m->szExePath;
#endif
    BaseAddress = (uint64_t)m->modBaseAddr;
    pID = m->th32ProcessID;
    iSize = m->modBaseSize;
}

void Memory::getProcess(const char* processName, PROCESSENTRY32* process) {
#ifndef _MBCS
    std::wstring wprocessName;
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> s2wconverter;
#endif
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    process->dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, process) == 0)
        CloseHandle(hSnap);
#ifndef _MBCS
    wprocessName = s2wconverter.from_bytes(processName);
#endif
    do {
#ifndef _MBCS
        if (lstrcmp(process->szExeFile, &wprocessName[0]) == 0)
#else
        if (lstrcmp(process->szExeFile, processName) == 0)
#endif
            break;
    } while (Process32Next(hSnap, process));
    CloseHandle(hSnap);

    return;
}

void Memory::getModule(const char* moduleName, MODULEENTRY32* module, PROCESSENTRY32* process) {
#ifndef _MBCS
    std::wstring wmoduleName;
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> s2wconverter;
#endif
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process->th32ProcessID);

    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    module->dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hSnap, module) == 0)
        CloseHandle(hSnap);
#ifndef _MBCS
    wmoduleName = s2wconverter.from_bytes(moduleName);
#endif
    do {
#ifndef _MBCS
        if (lstrcmp(module->szModule, &wmoduleName[0]) == 0)
#else
        if (lstrcmp(module->szModule, moduleName) == 0)
#endif
            break;
    } while (Module32Next(hSnap, module));
    CloseHandle(hSnap);

    return;
}

bool Memory::isHex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool Memory::createPattern(const std::string& pattern, std::string& pattern_result, std::string& mask_result) {
    bool result = false;
    char buffer[2];
    std::stringstream pattern_s;
    std::stringstream mask_s;

    if (pattern.empty())
        return result;

    for (size_t i = 0, l = pattern.size() - 1; i < l; i++) {
        if (isHex(pattern[i])) {
            buffer[0] = pattern[i];
            buffer[1] = (l >= i + 1 && isHex(pattern[i + 1])) ? pattern[++i] : 0;
            pattern_s << (char)strtol(buffer, nullptr, 16);
            mask_s << 'x';
            continue;
        }
        else if (pattern[i] == '?' || pattern[i] == '*') {
            pattern_s << "\x90";
            mask_s << '?';
            continue;
        }
    }
    result = true;
    pattern_result = pattern_s.str();
    mask_result = mask_s.str();

    return result;
}

uint64_t Memory::patternScan(const std::string& pattern, uint64_t startAddress) {
    std::string sub_ptr;
    std::string sub_mask;
    createPattern(pattern, sub_ptr, sub_mask);
    return patternScan(&sub_ptr[0], sub_mask, startAddress);
}

uint64_t Memory::patternScan(char* sig, std::string pattern, uint64_t startAddress) {
    uint64_t ret = 0;
    if (startAddress < BaseAddress || startAddress > (BaseAddress + iSize))
        startAddress = BaseAddress;
    char* cBuffer = new char[iSize];
    ReadProcessMemory(pHandle, (void*)startAddress, cBuffer, iSize, 0);
    size_t patternLength = pattern.size() - 1;

    for (size_t i = 0, j = 0; i != iSize; i++) {
        if (cBuffer[i] == sig[j] || pattern[j] == '?') {
            if (j == patternLength) {
                ret = (startAddress + i - j);
                goto PATTERN_SCAN_END;
            }

            j++;
        }
        else if (j > 0 && (cBuffer[i] == sig[0] || pattern[0] == '?')) {
            j = 1;
        }
        else {
            j = 0;
        }
    }
PATTERN_SCAN_END:
    delete[] cBuffer;
    return ret;
}

uint64_t Memory::getAddress(uint64_t Address, offsets offsets) {
    uint64_t nAddress = Address;
    if (Address == 0)
        return nAddress;
    size_t size = offsets.size() - 1;
    if (offsets.empty())
        return nAddress;

    ReadProcessMemory(pHandle, (void*)nAddress, &nAddress, sizeof(nAddress), 0);
    for (size_t i = 0; i != size; i++)
        ReadProcessMemory(pHandle, (void*)(nAddress + offsets[i]), &nAddress, sizeof(nAddress), 0);
    nAddress = nAddress + offsets[size];

    return nAddress;
}

std::string Memory::readString(uint64_t Address, int size, offsets offsets) {
    std::string ret;
    if (Address == 0)
        return ret;
    uint64_t nAddress = getAddress(Address, offsets);
    char* buffer = new char[size];
    ReadProcessMemory(pHandle, (void*)nAddress, buffer, size, 0);
    ret = std::string(buffer);
    delete[] buffer;
    return ret;
}

void Memory::writeString(uint64_t Address, std::string& str, offsets offsets) {
    uint64_t nAddress = getAddress(Address, offsets);
    WriteProcessMemory(pHandle, (void*)nAddress, &str[0], str.size(), 0);
    return;
}

int main() {
    Memory GTA("GTA5.exe");
    uint64_t world = GTA.patternScan("48 8B 05 ? ? ? ? 45 ? ? ? ? 48 8B 48 08 48 85 C9 74 07");
    world = world + GTA.read<int>(world + 3) + 7;
    float Health = GTA.read<float>(world, { 8, 0x280 });
    std::cout << "Health is " << Health << std::endl;
    std::string name = GTA.readString(world, 12, { 8, 0x10B8, 0x7C });
    std::cout << "Playername: " << name << std::endl;
    std::cin.get();
    return 0;
}
